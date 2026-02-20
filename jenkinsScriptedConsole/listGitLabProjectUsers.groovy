import groovy.json.JsonSlurper
import groovy.json.JsonOutput

// === 설정 부분 ===
def gitlabUrl = "https://gitlab.example.com" // 본인의 GitLab 주소로 변경
def apiToken = "YOUR_PRIVATE_TOKEN"          // 본인의 API 토큰으로 변경
def sourceProjectId = "123"                  // 원본 프로젝트 ID
def targetSubgroupId = "456"                 // 대상 서브그룹 ID
// ================

def headers = [
    "PRIVATE-TOKEN": apiToken,
    "Content-Type": "application/json"
]

// 1. 프로젝트의 모든 멤버 가져오기 (상속된 멤버 포함: /all)
println "--- 프로젝트(ID: ${sourceProjectId}) 멤버 목록 조회 시작 ---"
def membersUrl = "${gitlabUrl}/api/v4/projects/${sourceProjectId}/members/all"
def membersJson = new URL(membersUrl).openConnection()
headers.each { k, v -> membersJson.setRequestProperty(k, v) }

if (membersJson.responseCode != 200) {
    println "에러: 프로젝트 멤버를 가져올 수 없습니다. (코드: ${membersJson.responseCode})"
    return
}

def members = new JsonSlurper().parseText(membersJson.inputStream.text)
println "조회된 멤버 수: ${members.size()}명"

// 2. 각 멤버를 Subgroup에 추가
println "--- Subgroup(ID: ${targetSubgroupId})으로 멤버 복사 시작 ---"

members.each { member ->
    // 권한(access_level)이 최소 Developer(30) 이상인 경우에만 CODEOWNERS 승인권이 유효함
    println "처리 중: ${member.username} (권한: ${member.access_level})"

    def addMemberUrl = "${gitlabUrl}/api/v4/groups/${targetSubgroupId}/members"
    def post = new URL(addMemberUrl).openConnection()
    post.setRequestMethod("POST")
    headers.each { k, v -> post.setRequestProperty(k, v) }
    post.setDoOutput(true)

    def payload = JsonOutput.toJson([
        user_id: member.id,
        access_level: member.access_level
    ])

    try {
        post.outputStream.write(payload.getBytes("UTF-8"))
        def responseCode = post.responseCode
        
        if (responseCode == 201) {
            println "  => 성공: ${member.username} 추가됨"
        } else if (responseCode == 409) {
            println "  => 건너뜀: ${member.username}은(는) 이미 그룹에 존재함"
        } else {
            println "  => 실패: ${member.username} (오류 코드: ${responseCode})"
        }
    } catch (Exception e) {
        println "  => 예외 발생: ${e.message}"
    }
}

println "--- 모든 작업이 완료되었습니다 ---"
