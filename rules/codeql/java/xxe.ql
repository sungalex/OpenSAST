/**
 * @name XML 외부 개체 참조(XXE)
 * @description XML 파서에서 외부 엔티티 처리를 비활성화하지 않아
 *              XXE 공격에 노출된다.
 *              행안부 SR1-7 / CWE-611 에 해당한다.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision high
 * @id mois/sr1-7-xxe
 * @tags security
 *       mois/sr1-7
 *       external/cwe/cwe-611
 */

import java

/**
 * DocumentBuilderFactory.newInstance() 호출을 통해 생성된 팩토리 인스턴스.
 */
class DocumentBuilderFactoryInstance extends MethodAccess {
  DocumentBuilderFactoryInstance() {
    this.getMethod().hasName("newInstance") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.xml.parsers", "DocumentBuilderFactory")
  }
}

/**
 * SAXParserFactory.newInstance() 호출을 통해 생성된 팩토리 인스턴스.
 */
class SAXParserFactoryInstance extends MethodAccess {
  SAXParserFactoryInstance() {
    this.getMethod().hasName("newInstance") and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.xml.parsers", "SAXParserFactory")
  }
}

/**
 * XMLInputFactory.newInstance() / newFactory() 호출을 통해 생성된 팩토리 인스턴스.
 */
class XMLInputFactoryInstance extends MethodAccess {
  XMLInputFactoryInstance() {
    this.getMethod().hasName(["newInstance", "newFactory"]) and
    this.getMethod().getDeclaringType().hasQualifiedName("javax.xml.stream", "XMLInputFactory")
  }
}

/**
 * setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) 호출.
 */
class DisallowDoctypeCall extends MethodAccess {
  DisallowDoctypeCall() {
    this.getMethod().hasName("setFeature") and
    this.getAnArgument().(StringLiteral).getValue() =
      "http://apache.org/xml/features/disallow-doctype-decl" and
    this.getAnArgument().(BooleanLiteral).getBooleanValue() = true
  }
}

/**
 * setProperty(XMLInputFactory.SUPPORT_DTD / XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false) 호출.
 */
class DisableDtdPropertyCall extends MethodAccess {
  DisableDtdPropertyCall() {
    this.getMethod().hasName("setProperty") and
    (
      this.getAnArgument().(StringLiteral).getValue() = "javax.xml.stream.supportDTD" or
      this.getAnArgument().(StringLiteral).getValue() = "javax.xml.stream.isSupportingExternalEntities"
    ) and
    this.getAnArgument().(BooleanLiteral).getBooleanValue() = false
  }
}

/**
 * 동일 메서드 내에서 팩토리 생성 후 보안 설정이 적용되었는지 확인.
 */
predicate hasSecureConfig(MethodAccess factory) {
  exists(DisallowDoctypeCall d |
    d.getEnclosingCallable() = factory.getEnclosingCallable()
  )
  or
  exists(DisableDtdPropertyCall d |
    d.getEnclosingCallable() = factory.getEnclosingCallable()
  )
}

from MethodAccess factory
where
  (
    factory instanceof DocumentBuilderFactoryInstance or
    factory instanceof SAXParserFactoryInstance or
    factory instanceof XMLInputFactoryInstance
  ) and
  not hasSecureConfig(factory)
select factory,
  "SR1-7: XML 외부 개체 참조(XXE) — XML 파서에 disallow-doctype-decl 또는 DTD 비활성화 설정이 누락되었습니다."
