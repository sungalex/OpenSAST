/**
 * @name SQL 삽입(SQL Injection) — 오염된 입력의 SQL 전달
 * @description 사용자 입력이 검증 없이 SQL 쿼리 실행 메서드에 도달한다.
 *              행안부 SR1-1 / CWE-89 에 해당한다.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id mois/sr1-1-sql-injection-taint
 * @tags security
 *       mois/sr1-1
 *       external/cwe/cwe-89
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SqlInjectionQuery
import DataFlow::PathGraph

from SqlInjection::SqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SR1-1: SQL 삽입 — 사용자 입력이 SQL 쿼리에 도달합니다."
