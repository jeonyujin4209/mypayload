# SAP

## ODATA 란
OData (Open Data Protocol) 는 마이크로소프트가 만든 REST 기반의 표준 프로토콜로,
데이터 조회(Create, Read, Update, Delete) 를 HTTP + URL + JSON/XML 조합으로 처리
-> GET /sap/opu/odata/sap/ZEMPLOYEE_SRV/EmployeeSet?$filter=Dept eq 'HR'


## metadata
GET /sap/opu/odata/sap/ZEMPLOYEE_SRV/$metadata
<EntityType Name="Employee">
  <Key>
    <PropertyRef Name="EmpId" />
  </Key>
  <Property Name="EmpId" Type="Edm.String" Nullable="false"/>
  <Property Name="Name" Type="Edm.String"/>
  <Property Name="Dept" Type="Edm.String"/>
  <Property Name="JoinDate" Type="Edm.DateTime"/>
</EntityType>

<Property Name="EmpId"
          Type="Edm.String"
          Nullable="false"
          sap:filterable="true"
          sap:sortable="true"
          sap:creatable="false"
          sap:updatable="false" />



## 쿼리문 
예: User?$expand=empJob
$filter=   조건 필터, SQL의 WHERE 절과 유사 (status eq 'active')
$format=   응답 포맷 지정 (json, xml, atom 등)
$from=   특정 테이블 또는 뷰 지정 (v4 이상), SAP에선 거의 사용 안 됨
$orderby=   정렬 조건, 예: startDate desc
$search=   전체 텍스트 검색 (SAP는 거의 미지원)
$select=   반환할 필드 지정 (속도 최적화 및 데이터 축소에 사용)
$skip=   페이징 – 건너뛸 데이터 수 지정
$skiptoken=   페이징 시 서버가 제공하는 다음 페이지 토큰
$to=   effectiveEndDate le $to 같은 조건용. HR 유효기간 쿼리에 쓰임
$toInclusive=   effectiveEndDate le $toInclusive 와 유사. 마지막 날짜 포함 여부 제어
$top=   최대 몇 건까지 가져올지 제한 (LIMIT 역할)



## 실제 나왔던 것

$filter=name+eq+test 일때
$filter=name+ne+test으로 자신 제외 전체 조회 가능.

프로퍼티의 password 검증이 미흡할 경우 계정 탈취 가능.
