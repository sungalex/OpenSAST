/**
 * @name 안전하지 않은 역직렬화(Unsafe Deserialization)
 * @description ObjectInputStream.readObject()를 화이트리스트 검증 없이
 *              사용하여 임의 객체 역직렬화 공격에 노출된다.
 *              행안부 SR1-18 / CWE-502 에 해당한다.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id mois/sr1-18-unsafe-deserialization
 * @tags security
 *       mois/sr1-18
 *       external/cwe/cwe-502
 */

import java

/**
 * ObjectInputStream.readObject() 또는 readUnshared() 호출.
 */
class UnsafeReadObjectCall extends MethodAccess {
  UnsafeReadObjectCall() {
    this.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("java.io", "ObjectInputStream") and
    this.getMethod().hasName(["readObject", "readUnshared"])
  }
}

/**
 * ObjectInputFilter (Java 9+) 또는 Apache Commons IO ValidatingObjectInputStream 등
 * 화이트리스트 기반 필터가 적용되었는지 확인.
 */
predicate hasDeserializationFilter(UnsafeReadObjectCall readCall) {
  exists(MethodAccess filterCall |
    filterCall.getEnclosingCallable() = readCall.getEnclosingCallable() and
    filterCall.getLocation().getStartLine() <= readCall.getLocation().getStartLine() and
    (
      // ObjectInputStream.setObjectInputFilter() (Java 9+)
      filterCall.getMethod().hasName("setObjectInputFilter") or
      // ObjectInputFilter.Config.setSerialFilter() (글로벌 필터)
      filterCall.getMethod().hasName("setSerialFilter") or
      // Apache Commons IO ValidatingObjectInputStream.accept()
      filterCall.getMethod().hasName("accept")
    )
  )
}

/**
 * 커스텀 ObjectInputStream 서브클래스에서 resolveClass()를 오버라이드한 경우.
 */
predicate usesCustomObjectInputStream(UnsafeReadObjectCall readCall) {
  exists(RefType subtype |
    subtype.getASupertype*().hasQualifiedName("java.io", "ObjectInputStream") and
    not subtype.hasQualifiedName("java.io", "ObjectInputStream") and
    exists(Method resolveClass |
      resolveClass.getDeclaringType() = subtype and
      resolveClass.hasName("resolveClass")
    ) and
    readCall.getQualifier().getType() = subtype
  )
}

from UnsafeReadObjectCall readCall
where
  not hasDeserializationFilter(readCall) and
  not usesCustomObjectInputStream(readCall)
select readCall,
  "SR1-18: 안전하지 않은 역직렬화 — ObjectInputStream.readObject() 호출에 " +
  "화이트리스트 필터(ObjectInputFilter 또는 resolveClass 오버라이드)가 적용되지 않았습니다."
