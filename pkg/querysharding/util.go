package querysharding

import (
	"encoding/base64"
	"net/http"
	"sync"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/thanos-io/thanos/pkg/store/storepb"
	"github.com/weaveworks/common/httpgrpc"
)

const (
	CortexShardByLabel = "__CORTEX_SHARD_BY__"

	// MaxPromQLASTDepth bounds the depth of the parsed PromQL AST that InjectShardingInfo is
	// willing to walk and re-serialise. See pkg/querier/tripperware.MaxPromQLASTDepth for the
	// rationale; both values are kept in sync intentionally.
	MaxPromQLASTDepth = 1000
)

var (
	buffers = sync.Pool{New: func() interface{} {
		b := make([]byte, 0, 100)
		return &b
	}}
)

// validateASTDepth walks the parsed AST iteratively with an explicit worklist and returns an
// HTTP 400 error if any path from the root to a leaf is deeper than maxDepth. The walk itself
// does not grow the goroutine stack, so it is safe to run on untrusted input before any
// recursive Walk / String call.
func validateASTDepth(expr parser.Node, maxDepth int) error {
	if expr == nil || maxDepth <= 0 {
		return nil
	}
	type frame struct {
		node  parser.Node
		depth int
	}
	stack := []frame{{node: expr, depth: 1}}
	for len(stack) > 0 {
		top := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if top.depth > maxDepth {
			return httpgrpc.Errorf(http.StatusBadRequest,
				"query expression nesting depth exceeds the limit of %d", maxDepth)
		}
		for _, child := range parser.Children(top.node) {
			if child == nil {
				continue
			}
			stack = append(stack, frame{node: child, depth: top.depth + 1})
		}
	}
	return nil
}

func InjectShardingInfo(query string, shardInfo *storepb.ShardInfo) (string, error) {
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}
	if err := validateASTDepth(expr, MaxPromQLASTDepth); err != nil {
		return "", err
	}
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

	return expr.String(), err
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
