/**
 * @name 정수 오버플로우(Integer Overflow)
 * @description 범위 검증 없는 산술 연산으로 인해 정수 오버플로우가
 *              발생할 수 있다.
 *              행안부 SR1-13 / CWE-190 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id mois/sr1-13-integer-overflow
 * @tags security
 *       mois/sr1-13
 *       external/cwe/cwe-190
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

/**
 * 사용자 입력(원격 소스)으로부터 전달된 정수 값.
 */
class RemoteIntSource extends DataFlow::Node {
  RemoteIntSource() {
    this instanceof RemoteFlowSource and
    this.getType() instanceof IntegralType
  }
}

/**
 * 산술 오버플로우 위험이 있는 이항 연산(+, -, *, <<).
 * 결과 타입이 int 또는 long 인 경우만 대상으로 한다.
 */
class OverflowProneBinaryExpr extends BinaryExpr {
  OverflowProneBinaryExpr() {
    (
      this instanceof AddExpr or
      this instanceof SubExpr or
      this instanceof MulExpr or
      this instanceof LShiftExpr
    ) and
    this.getType() instanceof IntegralType
  }
}

/**
 * 타입 캐스팅으로 인한 축소(narrowing) — long/int 에서 short/byte 로의 캐스트.
 */
class NarrowingCast extends CastExpr {
  NarrowingCast() {
    this.getExpr().getType().(IntegralType).getWidthRank() >
    this.getType().(IntegralType).getWidthRank()
  }
}

/**
 * 범위 검증(비교 조건문)이 연산 이전에 수행되었는지 확인.
 */
predicate hasBoundsCheck(Expr operand) {
  exists(ComparisonExpr cmp, IfStmt ifStmt |
    (cmp.getAnOperand() = operand or
     cmp.getAnOperand().(VarAccess).getVariable() = operand.(VarAccess).getVariable()) and
    ifStmt.getCondition() = cmp and
    ifStmt.getLocation().getStartLine() <= operand.getLocation().getStartLine()
  )
}

from OverflowProneBinaryExpr expr
where
  not hasBoundsCheck(expr.getAnOperand()) and
  (
    // 산술 연산의 피연산자 중 하나가 메서드 파라미터이거나 외부 입력일 때
    exists(Parameter p |
      expr.getAnOperand().(VarAccess).getVariable() = p
    )
    or
    exists(MethodAccess ma |
      expr.getAnOperand() = ma and
      ma.getMethod().hasName(["parseInt", "parseLong", "intValue", "longValue",
                              "nextInt", "nextLong", "readInt", "readLong"])
    )
  )
select expr,
  "SR1-13: 정수 오버플로우 — 범위 검증 없이 산술 연산(" + expr.getOp() +
  ")이 수행됩니다. Math.addExact/multiplyExact 또는 사전 범위 검증을 권장합니다."
