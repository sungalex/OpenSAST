/**
 * @name 반환값 무시(Unchecked Return Value)
 * @description File.delete(), File.mkdir() 등 실패 가능한 메서드의
 *              반환값을 확인하지 않아 오류가 무시된다.
 *              행안부 SR5-7 / CWE-252 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @security-severity 4.0
 * @precision high
 * @id mois/sr5-7-unchecked-return
 * @tags security
 *       mois/sr5-7
 *       external/cwe/cwe-252
 */

import java

/**
 * 반환값 확인이 필수적인 메서드 목록.
 * boolean 반환 타입으로 성공/실패를 알리지만 흔히 무시되는 메서드들.
 */
class MustCheckReturnMethod extends Method {
  MustCheckReturnMethod() {
    this.getReturnType() instanceof BooleanType and
    (
      // java.io.File 의 파일 시스템 조작 메서드
      (
        this.getDeclaringType().hasQualifiedName("java.io", "File") and
        this.hasName([
          "delete", "mkdir", "mkdirs", "renameTo",
          "setReadable", "setWritable", "setExecutable",
          "setLastModified", "setReadOnly", "createNewFile"
        ])
      )
      or
      // java.util.concurrent.locks.Lock.tryLock()
      (
        this.getDeclaringType().getASupertype*().hasQualifiedName("java.util.concurrent.locks", "Lock") and
        this.hasName("tryLock")
      )
      or
      // java.util.concurrent 큐 오퍼레이션
      (
        this.getDeclaringType().getASupertype*().hasQualifiedName("java.util.concurrent", "BlockingQueue") and
        this.hasName(["offer", "remove"])
      )
      or
      // java.util.Collection.add/remove (Set 등에서 중복 확인)
      (
        this.getDeclaringType().getASupertype*().hasQualifiedName("java.util", "Set") and
        this.hasName(["add", "remove"])
      )
      or
      // SecurityManager 관련
      (
        this.getDeclaringType().hasQualifiedName("java.lang", "SecurityManager") and
        this.hasName("checkPermission")
      )
    )
  }
}

/**
 * 메서드 호출의 반환값이 사용(변수 대입, 조건문, 인자 등)되는지 확인.
 */
predicate returnValueUsed(MethodAccess ma) {
  exists(AssignExpr assign | assign.getSource() = ma) or
  exists(LocalVariableDeclExpr decl | decl.getInit() = ma) or
  exists(IfStmt ifStmt | ifStmt.getCondition().getAChildExpr*() = ma) or
  exists(WhileStmt ws | ws.getCondition().getAChildExpr*() = ma) or
  exists(ReturnStmt ret | ret.getResult() = ma) or
  exists(ConditionalExpr ce | ce.getAChildExpr() = ma) or
  exists(LogicalAndExpr lae | lae.getAChildExpr*() = ma) or
  exists(LogicalOrExpr loe | loe.getAChildExpr*() = ma) or
  exists(UnaryExpr ue | ue.getExpr() = ma) or
  exists(MethodAccess outer | outer.getAnArgument() = ma)
}

from MethodAccess call
where
  call.getMethod() instanceof MustCheckReturnMethod and
  not returnValueUsed(call)
select call,
  "SR5-7: 반환값 무시 — " + call.getMethod().getDeclaringType().getName() + "." +
  call.getMethod().getName() + "()의 반환값을 확인하지 않습니다. " +
  "실패 시 오류가 무시될 수 있습니다."
