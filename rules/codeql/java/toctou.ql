/**
 * @name 검사시점과 사용시점 경쟁조건(TOCTOU)
 * @description 파일 존재 여부 확인 직후 동일 파일을 수정/삭제하는 패턴 감지.
 *              행안부 SR3-1 / CWE-367 에 해당한다.
 * @kind problem
 * @problem.severity warning
 * @id mois/sr3-1-toctou-race-condition
 * @tags security
 *       external/cwe/cwe-367
 *       mois/sr3-1
 */

import java

class FileExistsCheck extends MethodAccess {
  FileExistsCheck() {
    this.getMethod().hasName("exists") and
    this.getMethod().getDeclaringType().hasQualifiedName("java.io", "File")
  }
}

class MutatingFileUse extends MethodAccess {
  MutatingFileUse() {
    this.getMethod().getDeclaringType().hasQualifiedName("java.io", "File") and
    this.getMethod().hasName([
        "delete", "renameTo", "createNewFile", "mkdir", "mkdirs",
        "setReadable", "setWritable", "setExecutable"
      ])
  }
}

from FileExistsCheck check, MutatingFileUse use, Expr q
where
  q = check.getQualifier() and
  q.getType() = use.getQualifier().getType() and
  check.getEnclosingCallable() = use.getEnclosingCallable() and
  check.getLocation().getStartLine() < use.getLocation().getStartLine()
select use,
  "TOCTOU 경쟁조건: exists() 확인(" + check.getLocation().getStartLine() +
  "행) 이후 동일 파일에 대한 파괴적 작업 발생. 파일을 한 번에 처리하는 API 사용을 권장합니다."
