node {
    // ---------------------------------------------------------
    // 설정 변수 (사용 환경에 맞게 수정하세요)
    // ---------------------------------------------------------
    final String BLACKDUCK_URL = "https://your-blackduck-server.com" 
    final String projectName = "your-project-name" 
    final String credentialsId = "blackduck-token-id" // Jenkins Secret Text Credential ID

    stage('Black Duck CVE Report') {
        // Jenkins Credentials Store에서 토큰 로드
        withCredentials([string(credentialsId: credentialsId, variable: 'BD_TOKEN')]) {
            
            // 1. Black Duck API 인증 (Bearer 토큰 발급)
            echo "Black Duck 인증 진행 중..."
            
            def authResponse = httpRequest(
                url: "${BLACKDUCK_URL}/api/tokens/authenticate",
                httpMode: 'POST',
                contentType: 'APPLICATION_JSON',
                acceptType: 'APPLICATION_JSON',
                customHeaders: [
                    [name: 'Accept', value: 'application/vnd.blackducksoftware.user-4+json'],
                    [name: 'Authorization', value: "token ${BD_TOKEN}"]
                ],
                validResponseCodes: '200'
            )
            
            // NotSerializableException 방지를 위해 인라인으로 JSON 파싱
            def authJson = new groovy.json.JsonSlurperClassic().parseText(authResponse.content)
            def bearerToken = authJson.bearerToken
            
            if (!bearerToken) {
                error "Black Duck 인증 실패: 토큰을 발급받을 수 없습니다."
            }
            echo "✓ 인증 성공"

            // 2. 프로젝트 검색 (URL 인코딩 적용)
            echo "프로젝트 '${projectName}' 검색 중..."
            def encodedProjectName = java.net.URLEncoder.encode(projectName, "UTF-8")
            
            def projectResponse = httpRequest(
                url: "${BLACKDUCK_URL}/api/projects?q=name:${encodedProjectName}",
                httpMode: 'GET',
                contentType: 'APPLICATION_JSON',
                customHeaders: [
                    [name: 'Accept', value: 'application/vnd.blackducksoftware.project-detail-5+json'],
                    [name: 'Authorization', value: "Bearer ${bearerToken}"]
                ],
                validResponseCodes: '200'
            )
            
            def projectData = new groovy.json.JsonSlurperClassic().parseText(projectResponse.content)
            
            if (!projectData.items || projectData.items.isEmpty()) {
                error "프로젝트 '${projectName}'을 찾을 수 없습니다. 검색 결과가 비어있습니다."
            }
            
            // 정확히 일치하는 프로젝트 찾기
            def project = projectData.items.find { it.name == projectName }
            
            if (!project) {
                echo "경고: 정확히 일치하는 프로젝트를 찾지 못했습니다. 검색된 프로젝트 목록:"
                projectData.items.each { echo "  - ${it.name}" }
                error "프로젝트 '${projectName}'과 정확히 일치하는 항목이 없습니다."
            }
            
            def projectUrl = project._meta.href
            echo "✓ 프로젝트 발견: ${project.name}"

            // 3. 최신 버전 조회 (생성일 기준 내림차순 정렬하여 첫 번째 항목 선택)
            echo "최신 버전 정보를 조회 중입니다..."
            
            def versionsResponse = httpRequest(
                url: "${projectUrl}/versions?sort=createdAt%20desc&limit=1&offset=0",
                httpMode: 'GET',
                contentType: 'APPLICATION_JSON',
                customHeaders: [
                    [name: 'Accept', value: 'application/vnd.blackducksoftware.project-detail-5+json'],
                    [name: 'Authorization', value: "Bearer ${bearerToken}"]
                ],
                validResponseCodes: '200'
            )
            
            def versionsData = new groovy.json.JsonSlurperClassic().parseText(versionsResponse.content)
            if (!versionsData.items || versionsData.items.isEmpty()) {
                error "해당 프로젝트에 등록된 버전이 없습니다."
            }
            
            def latestVersion = versionsData.items[0]
            echo "✓ 최신 버전 확인: ${latestVersion.versionName}"
            def versionUrl = latestVersion._meta.href

            // 4. 취약점 목록(Vulnerable BOM Components) 조회 - 페이지네이션 적용
            echo "취약점 Bill of Materials(BOM)을 분석 중입니다..."
            
            // ID를 키로 사용하여 중복 제거 및 최고 점수 유지
            def cveMap = [:] 
            int offset = 0
            int limit = 100 
            boolean hasMore = true
            
            while (hasMore) {
                echo "Fetching vulnerabilities (offset: ${offset}, limit: ${limit})..."
                
                def vulnerabilitiesResponse = httpRequest(
                    url: "${versionUrl}/vulnerable-bom-components?limit=${limit}&offset=${offset}",
                    httpMode: 'GET',
                    contentType: 'APPLICATION_JSON',
                    customHeaders: [
                        [name: 'Accept', value: 'application/vnd.blackducksoftware.bill-of-materials-6+json'],
                        [name: 'Authorization', value: "Bearer ${bearerToken}"]
                    ],
                    validResponseCodes: '200'
                )
                
                def vulnerabilitiesData = new groovy.json.JsonSlurperClassic().parseText(vulnerabilitiesResponse.content)
                
                // 조회된 항목이 없으면 루프 종료
                if (!vulnerabilitiesData.items || vulnerabilitiesData.items.isEmpty()) {
                    hasMore = false
                    break
                }
                
                int itemsCount = vulnerabilitiesData.items.size()
                echo "  - ${itemsCount}개의 컴포넌트 항목 조회됨"
                
                vulnerabilitiesData.items.each { item ->
                    // vulnerabilityWithRemediation 객체 확인
                    if (!item.vulnerabilityWithRemediation) {
                        return // continue to next item
                    }
                    
                    def vuln = item.vulnerabilityWithRemediation
                    def vulnId = vuln.vulnerabilityName
                    
                    // CVE-XXXX-XXXX 형식만 허용 (BDSA 제외)
                    if (vulnId && vulnId.startsWith("CVE-")) {
                        double scoreV3 = 0.0d
                        
                        // CVSS V3 점수 추출 (우선순위: cvss3.baseScore > baseScore > overallScore)
                        // API 응답 필드를 확인하여 Double로 변환
                        if (vuln.cvss3 != null && vuln.cvss3.baseScore != null) {
                            scoreV3 = vuln.cvss3.baseScore as Double
                        } else if (vuln.baseScore != null) {
                            scoreV3 = vuln.baseScore as Double
                        } else if (vuln.overallScore != null) {
                            scoreV3 = vuln.overallScore as Double
                        }
                        
                        // 이미 맵에 존재하면 점수 비교 후 높은 값 유지
                        if (!cveMap.containsKey(vulnId)) {
                            cveMap[vulnId] = [
                                id: vulnId,
                                score: scoreV3,
                                severity: vuln.severity ?: "UNKNOWN",
                                component: item.componentName ?: "N/A",
                                version: item.componentVersionName ?: "N/A"
                            ]
                        } else {
                            // 기존 점수보다 높으면 업데이트
                            if (scoreV3 > cveMap[vulnId].score) {
                                cveMap[vulnId] = [
                                    id: vulnId,
                                    score: scoreV3,
                                    severity: vuln.severity ?: "UNKNOWN",
                                    component: item.componentName ?: "N/A",
                                    version: item.componentVersionName ?: "N/A"
                                ]
                            }
                        }
                    }
                }
                
                // 페이지네이션 조건 확인
                int totalCount = vulnerabilitiesData.totalCount ?: 0
                offset += limit
                
                if (totalCount > 0) {
                    if (offset >= totalCount) {
                        hasMore = false
                    }
                } else {
                    if (itemsCount < limit) {
                        hasMore = false
                    }
                }
            }
            
            // Map의 값들만 추출하여 리스트로 변환
            def cveList = new ArrayList(cveMap.values())
            
            if (cveList.isEmpty()) {
                echo "================================================================"
                echo "  Black Duck CVE LIST : ${projectName} (${latestVersion.versionName})"
                echo "================================================================"
                echo "조회된 CVE 취약점이 없습니다. (BDSA는 필터링됨)"
                echo "================================================================"
                return
            }
            
            // 디버깅: 정렬 전 데이터 샘플 출력
            echo "정렬 전 데이터 샘플 (첫 3개): ${cveList.take(3).collect { it.score }}"
            
            // [정렬] 별도 메서드로 추출한 버블 정렬 호출
            cveList = sortCveListDesc(cveList)
            
            // 디버깅: 정렬 후 데이터 샘플 출력
            echo "정렬 후 데이터 샘플 (첫 3개): ${cveList.take(3).collect { it.score }}"

            // 6. 결과 출력
            echo "================================================================"
            echo "  Black Duck CVE LIST : ${projectName} (${latestVersion.versionName})"
            echo "================================================================"
            echo "총 ${cveList.size()}개의 고유 CVE 발견 (CVSS V3 점수 기준 정렬)"
            echo "----------------------------------------------------------------"
            cveList.each { cve ->
                println "[${cve.id}] Score: ${String.format('%.1f', cve.score)} | Severity: ${cve.severity} | Component: ${cve.component} (${cve.version})"
            }
            echo "================================================================"
        }
    }
}

// -----------------------------------------------------------------------------
// [Helper Method] 버블 정렬 (내림차순)
// @NonCPS: 파이프라인 지속성(CPS) 변환 대상에서 제외하여 구버전 호환성 확보 및 성능 개선
// -----------------------------------------------------------------------------
@NonCPS
List sortCveListDesc(List list) {
    def sortedList = new ArrayList(list)
    int n = sortedList.size()
    
    for (int i = 0; i < n - 1; i++) {
        for (int j = 0; j < n - 1 - i; j++) {
            double scoreA = sortedList[j].score as Double
            double scoreB = sortedList[j + 1].score as Double
            
            // 내림차순: 뒤의 요소(B)가 더 크면 교환
            if (scoreB > scoreA) {
                def temp = sortedList[j]
                sortedList[j] = sortedList[j + 1]
                sortedList[j + 1] = temp
            }
        }
    }
    return sortedList
}
