package authz

import (
	"fmt"
	"time"

	"github.com/google/cel-go/cel"

	"github.com/sylr/nats-oidc-callout/internal/identity"
)

// celCostLimit bounds the cost of a single CEL evaluation so an expensive
// expression cannot stall the callout hot path.
const celCostLimit = 1_000_000

// newCELEnv builds the CEL environment exposing the verified identity:
//   - sub    (string)              the token subject
//   - iss    (string)              the token issuer
//   - aud    (list<string>)        the token audiences
//   - claims (map<string,string>)  flattened claims (e.g. claims["repository"],
//     claims["aws.aws_account"]); values are strings — use int()/double() to
//     compare numerically
//   - exp    (timestamp)           the token expiry
//   - now    (timestamp)           evaluation time
func newCELEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("sub", cel.StringType),
		cel.Variable("iss", cel.StringType),
		cel.Variable("aud", cel.ListType(cel.StringType)),
		cel.Variable("claims", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("exp", cel.TimestampType),
		cel.Variable("now", cel.TimestampType),
	)
}

// compileCELProgram compiles a CEL expression that must evaluate to a bool.
func compileCELProgram(env *cel.Env, expr string) (cel.Program, error) {
	ast, iss := env.Compile(expr)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("invalid CEL expr: %w", iss.Err())
	}
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return nil, fmt.Errorf("CEL expr must evaluate to bool, got %s", ast.OutputType())
	}
	prg, err := env.Program(ast, cel.EvalOptions(cel.OptOptimize), cel.CostLimit(celCostLimit))
	if err != nil {
		return nil, fmt.Errorf("compile CEL program: %w", err)
	}
	return prg, nil
}

// evalCEL evaluates a compiled program against an identity. Any error (including
// a runtime type error or a cost-limit breach) is treated as "no match" so the
// rule fails closed.
func evalCEL(prg cel.Program, id *identity.Identity) bool {
	out, _, err := prg.Eval(map[string]any{
		"sub":    id.Subject,
		"iss":    id.Issuer,
		"aud":    id.Audience,
		"claims": id.Claims(),
		"exp":    id.Expiry,
		"now":    time.Now(),
	})
	if err != nil {
		return false
	}
	b, ok := out.Value().(bool)
	return ok && b
}
