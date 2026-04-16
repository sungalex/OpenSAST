/**
 * @name Use of uninitialized variable
 * @description Reading a local variable that may not have been initialized
 *              leads to unpredictable behavior.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id mois/sr5-4-uninitialized-variable
 * @tags security
 *       mois
 *       sr5-4
 *       cwe-457
 */

import java
import semmle.code.java.dataflow.SSA

from LocalVariableDeclExpr decl, VarAccess access
where
  access.getVariable() = decl.getVariable() and
  not exists(AssignExpr assign |
    assign.getDest().(VarAccess).getVariable() = decl.getVariable() and
    assign.getBasicBlock().bbDominates(access.getBasicBlock())
  ) and
  not exists(decl.getInit()) and
  decl.getVariable().getType() instanceof RefType
select access,
  "SR5-4: 초기화되지 않은 변수 사용 — 변수 '" + access.getVariable().getName() +
    "'이(가) 초기화 없이 사용될 수 있습니다. (CWE-457)"
