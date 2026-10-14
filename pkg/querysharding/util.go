package querysharding

import (
	"encoding/base64"
	"sync"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/thanos-io/thanos/pkg/store/storepb"
)

const (
	CortexShardByLabel = "__CORTEX_SHARD_BY__"
)

var (
	buffers = sync.Pool{New: func() interface{} {
		b := make([]byte, 0, 100)
		return &b
	}}
)

func InjectShardingInfo(query string, shardInfo *storepb.ShardInfo) (string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}
	return injectShardingInfoIntoExpr(expr, shardInfo)
}

// InjectShardingInfoBatch parses the query exactly once and produces one
// sharded query string per supplied shardInfo. The quadratic parse step is
// shared across all shards; only the (per-shard-cost-linear) AST mutation and
// re-serialisation runs N times. This is the production-safe analogue of
// calling InjectShardingInfo once per shard.
func InjectShardingInfoBatch(query string, shardInfos []*storepb.ShardInfo) ([]string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return nil, err
	}
	selectors := collectVectorSelectors(expr)

	// Pre-size each selector's LabelMatchers to avoid reallocating per shard.
	for _, s := range selectors {
		if cap(s.LabelMatchers) < len(s.LabelMatchers)+1 {
			nm := make([]*labels.Matcher, len(s.LabelMatchers), len(s.LabelMatchers)+1)
			copy(nm, s.LabelMatchers)
			s.LabelMatchers = nm
		}
	}

	out := make([]string, len(shardInfos))
	for i, info := range shardInfos {
		b, err := info.Marshal()
		if err != nil {
			return nil, err
		}
		eShardInfo := base64.StdEncoding.EncodeToString(b)
		m := &labels.Matcher{
			Type:  labels.MatchEqual,
			Name:  CortexShardByLabel,
			Value: eShardInfo,
		}
		// Append the shard-info matcher to each selector, serialise, then pop it
		// so the AST is clean for the next shard.
		for _, s := range selectors {
			s.LabelMatchers = append(s.LabelMatchers, m)
		}
		out[i] = expr.String()
		for _, s := range selectors {
			s.LabelMatchers = s.LabelMatchers[:len(s.LabelMatchers)-1]
		}
	}
	return out, nil
}

func injectShardingInfoIntoExpr(expr parser.Expr, shardInfo *storepb.ShardInfo) (string, error) {
	b, err := shardInfo.Marshal()
	if err != nil {
		return "", err
	}
	eShardInfo := base64.StdEncoding.EncodeToString(b)
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if selector, ok := n.(*parser.VectorSelector); ok {
			selector.LabelMatchers = append(selector.LabelMatchers, &labels.Matcher{
				Type:  labels.MatchEqual,
				Name:  CortexShardByLabel,
				Value: eShardInfo,
			})
		}
		return nil
	})
	return expr.String(), nil
}

func collectVectorSelectors(expr parser.Expr) []*parser.VectorSelector {
	var selectors []*parser.VectorSelector
	parser.Inspect(expr, func(n parser.Node, _ []parser.Node) error {
		if s, ok := n.(*parser.VectorSelector); ok {
			selectors = append(selectors, s)
		}
		return nil
	})
	return selectors
}

func ExtractShardingInfo(matchers []*labels.Matcher) ([]*labels.Matcher, *storepb.ShardInfo, error) {
	r := make([]*labels.Matcher, 0, len(matchers))

	shardInfo := storepb.ShardInfo{}
	for _, matcher := range matchers {
		if matcher.Name == CortexShardByLabel && matcher.Type == labels.MatchEqual {
			decoded, err := base64.StdEncoding.DecodeString(matcher.Value)
			if err != nil {
				return r, nil, err
			}
			err = shardInfo.Unmarshal(decoded)
			if err != nil {
				return r, nil, err
			}
		} else {
			r = append(r, matcher)
		}
	}

	return r, &shardInfo, nil
}

func ExtractShardingMatchers(matchers []*labels.Matcher) ([]*labels.Matcher, *storepb.ShardMatcher, error) {
	r, shardInfo, err := ExtractShardingInfo(matchers)

	if err != nil {
		return r, nil, err
	}

	return r, shardInfo.Matcher(&buffers), nil
}
