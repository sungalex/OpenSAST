/**
 * @name 경쟁 조건 — 동기화 없는 공유 필드 접근(Race Condition)
 * @description synchronized 블록 없이 여러 스레드에서 공유 필드에
 *              접근하여 경쟁 조건이 발생할 수 있다.
 *              행안부 SR5-5 / CWE-362 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id mois/sr5-5-race-condition
 * @tags security
 *       mois/sr5-5
 *       external/cwe/cwe-362
 */

import java

/**
 * static이 아닌 인스턴스 필드로, volatile/final 이 아닌 가변 필드.
 */
class SharedMutableField extends Field {
  SharedMutableField() {
    not this.isStatic() and
    not this.isFinal() and
    not this.isVolatile() and
    not this.getType() instanceof PrimitiveType and
    // 명시적으로 concurrent 패키지의 Atomic 타입은 제외
    not this.getType().getName().matches("Atomic%")
  }
}

/**
 * Runnable.run(), Thread.run(), Callable.call() 등 스레드 진입점 메서드.
 */
class ThreadEntryMethod extends Method {
  ThreadEntryMethod() {
    (
      this.hasName("run") and
      this.getNumberOfParameters() = 0 and
      (
        this.getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "Runnable") or
        this.getDeclaringType().getASupertype*().hasQualifiedName("java.lang", "Thread")
      )
    )
    or
    (
      this.hasName("call") and
      this.getDeclaringType().getASupertype*().hasQualifiedName("java.util.concurrent", "Callable")
    )
  }
}

/**
 * synchronized 블록/메서드 내에서 접근하는지 확인.
 */
predicate isSynchronizedAccess(FieldAccess fa) {
  fa.getEnclosingCallable().(Method).isSynchronized()
  or
  exists(SynchronizedStmt sync |
    fa.getEnclosingStmt().getParent*() = sync.getBlock()
  )
}

/**
 * 필드가 쓰기 접근되는지 확인 (대입문 좌변).
 */
predicate isFieldWrite(FieldAccess fa) {
  exists(AssignExpr assign | assign.getDest() = fa)
  or
  exists(UnaryAssignExpr unary | unary.getExpr() = fa)
}

from SharedMutableField field, FieldAccess write, FieldAccess threadRead
where
  // 같은 필드에 대한 쓰기(메인)와 읽기(스레드) 접근
  write.getField() = field and
  threadRead.getField() = field and
  // 쓰기가 존재
  isFieldWrite(write) and
  // 읽기가 스레드 진입점 메서드 내에서 발생
  threadRead.getEnclosingCallable() instanceof ThreadEntryMethod and
  // 동기화 없음
  not isSynchronizedAccess(write) and
  not isSynchronizedAccess(threadRead) and
  // 같은 클래스 내
  write.getEnclosingCallable().getDeclaringType() = threadRead.getEnclosingCallable().getDeclaringType()
select threadRead,
  "SR5-5: 경쟁 조건 — 필드 '" + field.getName() +
  "'이(가) synchronized 없이 스레드에서 접근됩니다. " +
  "쓰기 위치: " + write.getLocation().getStartLine() + "행."
