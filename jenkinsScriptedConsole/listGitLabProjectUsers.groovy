import groovy.json.JsonSlurper

// ==================== 설정 ====================
def GITLAB_URL = "https://your-gitlab.example.com"  // GitLab URL (끝에 / 없이)
def PROJECT_ID = "123"                               // 프로젝트 ID 또는 URL 인코딩된 경로
def PRIVATE_TOKEN = "glpat-xxxxxxxxxxxxxxxxxxxx"     // GitLab Personal Access Token
def PER_PAGE = 100
// ==============================================

def emails = []
def page = 1
def hasMore = true

while (hasMore) {
    def url = "${GITLAB_URL}/api/v4/projects/${PROJECT_ID}/members/all?per_page=${PER_PAGE}&page=${page}"

    def connection = new URL(url).openConnection()
    connection.setRequestMethod("GET")
    connection.setRequestProperty("PRIVATE-TOKEN", PRIVATE_TOKEN)
    connection.connect()

    def responseCode = connection.responseCode
    if (responseCode != 200) {
        println "ERROR: HTTP ${responseCode} on page ${page}"
        break
    }

    // 다음 페이지 여부 확인 (X-Next-Page 헤더)
    def nextPage = connection.getHeaderField("X-Next-Page")
    hasMore = nextPage != null && !nextPage.isEmpty()

    def responseBody = connection.inputStream.text
    def members = new JsonSlurper().parseText(responseBody)

    members.each { member ->
        def email = member.email ?: ""   // email 필드 (null 이면 빈 문자열)
        if (email) {
            emails << email
        }
    }

    println "Page ${page}: ${members.size()} members fetched (cumulative: ${emails.size()})"
    page++
}

println "\n===== 멤버 이메일 목록 (총 ${emails.size()}명) ====="
emails.each { email ->
    println email
}
