/**
 * @name 널 포인터 역참조(Null Pointer Dereference)
 * @description null 반환 가능성이 있는 값에 대해 null 검사 없이
 *              메서드를 호출한다.
 *              행안부 SR5-1 / CWE-476 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @precision medium
 * @id mois/sr5-1-null-deref
 * @tags security
 *       mois/sr5-1
 *       external/cwe/cwe-476
 */

import java
import semmle.code.java.dataflow.Nullness

/**
 * null을 반환할 가능성이 있는 메서드 호출.
 * - Map.get(), HashMap.get() 등 컬렉션 조회
 * - findFirst().orElse(null), Optional 관련 패턴
 * - @Nullable 어노테이션이 있는 메서드
 */
class NullReturningMethodCall extends MethodAccess {
  NullReturningMethodCall() {
    (
      // Map.get(), ConcurrentHashMap.get() 등
      this.getMethod().hasName("get") and
      this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.util", "Map")
    )
    or
    (
      // System.getProperty(), System.getenv()
      this.getMethod().getDeclaringType().hasQualifiedName("java.lang", "System") and
      this.getMethod().hasName(["getProperty", "getenv"])
    )
    or
    (
      // ServletRequest.getParameter(), getHeader(), getAttribute()
      this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet", "ServletRequest") and
      this.getMethod().hasName(["getParameter", "getHeader", "getAttribute"])
    )
    or
    (
      // Class.forName() 등 리플렉션
      this.getMethod().hasName(["getResource", "getResourceAsStream"]) and
      this.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Class")
    )
    or
    (
      // @Nullable 어노테이션 확인
      this.getMethod().getAnAnnotation().getType().hasName("Nullable")
    )
  }
}

/**
 * null 체크가 수행되었는지 판별.
 */
predicate hasNullCheck(VarAccess va) {
  exists(EqualityTest eq |
    eq.getAnOperand() = va.getVariable().getAnAccess() and
    eq.getAnOperand() instanceof NullLiteral and
    eq.getEnclosingCallable() = va.getEnclosingCallable()
  )
  or
  exists(MethodAccess ma |
    ma.getMethod().hasName(["nonNull", "requireNonNull", "isNull"]) and
    ma.getAnArgument() = va.getVariable().getAnAccess() and
    ma.getEnclosingCallable() = va.getEnclosingCallable()
  )
}

/**
 * null 반환 가능 메서드의 결과를 변수에 저장한 뒤,
 * null 체크 없이 해당 변수에서 메서드를 호출하는 패턴.
 */
from LocalVariableDecl var, NullReturningMethodCall src, MethodAccess deref
where
  var.getInit() = src and
  deref.getQualifier().(VarAccess).getVariable() = var and
  not hasNullCheck(deref.getQualifier()) and
  deref.getEnclosingCallable() = src.getEnclosingCallable()
select deref,
  "SR5-1: 널 포인터 역참조 — null 반환 가능한 " + src.getMethod().getName() +
  "()의 결과를 검사 없이 사용합니다."
