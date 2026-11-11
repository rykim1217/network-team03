# 검증 증적 이미지

개인 PC에서 확인한 화면 중 저장소에 넣어도 되는 캡처만 모았습니다.

| 파일 | 내용 |
| :--- | :--- |
| `pytest-results.png` | 루트 자동화 테스트 14건 통과 결과 |
| `git-remotes-status.png` | 개인 저장소(origin)와 팀 원본(upstream) 연결 및 작업 상태 |
| `repo-structure-team-and-local.png` | 팀 저장소와 로컬 프로젝트 전체 구조 |
| `github-install-files.png` | `pyproject.toml`, `requirements.txt`, 실행 스크립트와 README 위치 |
| `scenario1-bruteforce-results.png` | 시나리오 1 실제 브루트포스·자동 차단 실행 결과 |
| `scenario1-n8n-execution.png` | 시나리오 1 n8n 자동 대응 성공 실행 |
| `scenario1-discord-alert.png` | 시나리오 1 Discord 탐지·차단 알림 |
| `scenario1-20k-metrics.png` | 시나리오 1 2만 건 스파이크 최종 지표 |
| `scenario2-api-accepted.png` | 시나리오 2 키 폐기 전 HTTP 200 응답 |
| `scenario2-api-revoked.png` | 시나리오 2 키 폐기 후 HTTP 401 응답 |
| `scenario2-discord-alert.png` | 시나리오 2 키 폐기·교체·IP 차단 Discord 알림 |
| `scenario2-n8n-execution.png` | 시나리오 2 n8n 자동 대응 성공 실행 |
| `admin-security.png` | 시나리오 2 관리자 보안 화면 |
| `graylog-event-definition.png` | API 키 침해 이벤트 탐지와 n8n 전달 규칙 |
| `wazuh-rules.png` | Wazuh 규칙 관리 화면 |
| `pfsense-alias.png` | `EasyRuleBlockHostsWAN` 차단 별칭과 테스트 IP |
| `scenario3-discord-alerts.png` | 시나리오 3 CRITICAL·WARNING Discord 알림 |
| `scenario3-n8n-execution.png` | 시나리오 3 n8n Kill Chain 성공 실행 |

### 캡처 주석

시나리오 1 n8n 실행 캡처의 첫 Webhook 노드명이 `Scenario 2 Webhook`으로 표시되는 것은 원래 시나리오 1 허니토큰 워크플로가 빠지고 그 자리에 시나리오 2 워크플로가 들어간 상태이기 때문입니다. 캡처의 실행 ID 401은 실제로 시나리오 1 Brute Force 대응 흐름(공격자 IP 차단·Discord 알림·Graylog 응답)을 성공한 실행입니다.

실제 Discord 웹훅 주소가 표시되는 n8n 화면은 저장소에 포함하지 않았습니다. 제출할 때는 웹훅 주소를 가린 n8n 성공 실행 캡처를 별도로 추가하면 됩니다.

`증적캡처_부록.pdf`는 공통 자료 뒤에 시나리오 1(브루트포스), 시나리오 2(API Key Compromised), 시나리오 3(Kill Chain)별 증적을 각각 묶어 배치했습니다. 잘린 웹 기동 이미지는 제외했습니다.
