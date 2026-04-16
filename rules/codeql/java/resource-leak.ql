/**
 * @name 자원 해제 누락(Resource Leak)
 * @description Closeable/AutoCloseable 자원이 try-with-resources 또는
 *              finally 블록에서 해제되지 않아 자원 누수가 발생한다.
 *              행안부 SR5-2 / CWE-404, CWE-772 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @security-severity 5.0
 * @precision medium
 * @id mois/sr5-2-resource-leak
 * @tags security
 *       mois/sr5-2
 *       external/cwe/cwe-404
 *       external/cwe/cwe-772
 */

import java

/**
 * Closeable 또는 AutoCloseable 을 구현하는 타입의 인스턴스를 생성하는 표현식.
 */
class CloseableCreation extends ClassInstanceExpr {
  CloseableCreation() {
    this.getConstructedType().getASupertype*().hasQualifiedName("java.io", "Closeable") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.lang", "AutoCloseable")
  }
}

/**
 * 주요 자원 타입 필터 — 노이즈를 줄이기 위해 핵심 I/O 자원만 대상으로 한다.
 */
class ImportantCloseableCreation extends CloseableCreation {
  ImportantCloseableCreation() {
    this.getConstructedType().getASupertype*().hasQualifiedName("java.io", "InputStream") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.io", "OutputStream") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.io", "Reader") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.io", "Writer") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.sql", "Connection") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.sql", "Statement") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.sql", "ResultSet") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.sql", "PreparedStatement") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.net", "Socket") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.net", "ServerSocket") or
    this.getConstructedType().getASupertype*().hasQualifiedName("java.nio.channels", "Channel")
  }
}

/**
 * try-with-resources 문에서 자원으로 선언되었는지 확인.
 */
predicate isTryWithResource(LocalVariableDecl var) {
  exists(TryStmt tryStmt |
    tryStmt.getAResourceDecl().(LocalVariableDeclStmt).getAVariable() = var
  )
}

/**
 * finally 블록에서 close()가 호출되었는지 확인.
 */
predicate isClosedInFinally(LocalVariableDecl var) {
  exists(TryStmt tryStmt, MethodAccess closeCall |
    closeCall.getMethod().hasName("close") and
    closeCall.getQualifier().(VarAccess).getVariable() = var and
    closeCall.getEnclosingStmt().getParent*() = tryStmt.getFinally()
  )
}

/**
 * 메서드 반환값으로 전달되는 경우 (호출자에게 해제 책임 위임).
 */
predicate isReturnedOrPassed(LocalVariableDecl var) {
  exists(ReturnStmt ret |
    ret.getResult().(VarAccess).getVariable() = var
  )
  or
  exists(MethodAccess ma |
    ma.getAnArgument().(VarAccess).getVariable() = var and
    not ma.getMethod().hasName("close")
  )
}

from LocalVariableDecl var, ImportantCloseableCreation creation
where
  var.getInit() = creation and
  not isTryWithResource(var) and
  not isClosedInFinally(var) and
  not isReturnedOrPassed(var)
select creation,
  "SR5-2: 자원 해제 누락 — " + creation.getConstructedType().getName() +
  " 인스턴스가 try-with-resources 또는 finally 블록에서 해제되지 않습니다."
