/**
 * @name 서버사이드 요청 위조(SSRF)
 * @description 사용자 입력이 검증 없이 URL 연결에 사용되어
 *              내부 네트워크로 요청이 전달될 수 있다.
 *              행안부 SR1-11 / CWE-918 에 해당한다.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id mois/sr1-11-ssrf
 * @tags security
 *       mois/sr1-11
 *       external/cwe/cwe-918
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import DataFlow::PathGraph

/** HTTP 요청 파라미터 등 원격 사용자 입력 소스. */
class SsrfSource extends DataFlow::Node {
  SsrfSource() { this instanceof RemoteFlowSource }
}

/** URL 생성자 또는 URI.create() 에 전달되는 인자. */
class UrlConstructorSink extends DataFlow::Node {
  UrlConstructorSink() {
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = cc.getAnArgument()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("create") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URI") and
      this.asExpr() = ma.getAnArgument()
    )
    or
    exists(ConstructorCall cc |
      cc.getConstructedType().hasQualifiedName("java.net", "URI") and
      this.asExpr() = cc.getAnArgument()
    )
  }
}

/** HttpURLConnection.openConnection() 등 실제 연결을 수행하는 메서드의 qualifier. */
class OpenConnectionSink extends DataFlow::Node {
  OpenConnectionSink() {
    exists(MethodAccess ma |
      ma.getMethod().hasName("openConnection") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = ma.getQualifier()
    )
    or
    exists(MethodAccess ma |
      ma.getMethod().hasName("openStream") and
      ma.getMethod().getDeclaringType().hasQualifiedName("java.net", "URL") and
      this.asExpr() = ma.getQualifier()
    )
  }
}

class SsrfConfig extends TaintTracking::Configuration {
  SsrfConfig() { this = "SsrfConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SsrfSource
  }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof UrlConstructorSink or
    sink instanceof OpenConnectionSink
  }
}

from SsrfConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink,
  "SR1-11: 서버사이드 요청 위조(SSRF) — 사용자 입력이 URL 연결에 직접 사용됩니다."
