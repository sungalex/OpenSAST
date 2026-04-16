/**
 * @name 외부 입력에 의한 무한 반복(Unbounded Loop)
 * @description 외부 입력에 의해 제어되는 반복문이 탈출 조건 없이
 *              무한히 실행될 수 있다.
 *              행안부 SR3-2 / CWE-835 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id mois/sr3-2-unbounded-loop
 * @tags security
 *       mois/sr3-2
 *       external/cwe/cwe-835
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

/**
 * while/for 반복문의 조건절 또는 상한값에 외부 입력이 흘러들어가는 패턴.
 */
class ExternallyControlledLoopBound extends DataFlow::Node {
  ExternallyControlledLoopBound() {
    this instanceof RemoteFlowSource
  }
}

/**
 * 반복문(while/for)의 조건식에 사용되는 변수.
 */
class LoopConditionVarAccess extends VarAccess {
  LoopStmt loop;

  LoopConditionVarAccess() {
    (
      loop instanceof WhileStmt and this.getParent*() = loop.(WhileStmt).getCondition()
      or
      loop instanceof ForStmt and this.getParent*() = loop.(ForStmt).getCondition()
    )
  }

  LoopStmt getLoop() { result = loop }
}

/**
 * 반복문 내에 break, return, throw 등 탈출 구문이 있는지 확인.
 */
predicate hasEscapeStatement(LoopStmt loop) {
  exists(BreakStmt brk | brk.getEnclosingStmt+() = loop.getBody()) or
  exists(ReturnStmt ret | ret.getEnclosingStmt+() = loop.getBody()) or
  exists(ThrowStmt thr | thr.getEnclosingStmt+() = loop.getBody())
}

/**
 * 반복문의 반복 횟수에 상한(최대값) 제한이 있는지 확인.
 */
predicate hasMaxIterationGuard(LoopStmt loop) {
  exists(ComparisonExpr cmp |
    cmp.getParent*() = loop.(WhileStmt).getCondition() or
    cmp.getParent*() = loop.(ForStmt).getCondition()
  |
    // 상한값이 상수 리터럴이면 제한됨
    cmp.getAnOperand() instanceof IntegerLiteral or
    cmp.getAnOperand() instanceof LongLiteral or
    // Math.min 등으로 상한 제한
    exists(MethodAccess ma |
      ma.getMethod().hasName("min") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Math") and
      cmp.getAnOperand() = ma
    )
  )
}

class LoopBoundTaintConfig extends TaintTracking::Configuration {
  LoopBoundTaintConfig() { this = "LoopBoundTaintConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof ExternallyControlledLoopBound
  }

  override predicate isSink(DataFlow::Node sink) {
    sink.asExpr() instanceof LoopConditionVarAccess
  }
}

from
  LoopBoundTaintConfig config, DataFlow::Node source, DataFlow::Node sink,
  LoopConditionVarAccess condVar
where
  config.hasFlow(source, sink) and
  sink.asExpr() = condVar and
  not hasEscapeStatement(condVar.getLoop()) and
  not hasMaxIterationGuard(condVar.getLoop())
select condVar.getLoop(),
  "SR3-2: 외부 입력에 의한 무한 반복 — 사용자 입력이 반복문 조건에 사용되며, " +
  "탈출 조건 또는 최대 반복 횟수 제한이 없습니다."
