# CyberCare: AI-Powered Cyber Responder

An intelligent cybersecurity response system that leverages AI to detect, analyze, and respond to security threats in real-time.

## Features

- **AI-Driven Threat Analysis**: Utilizes machine learning to identify and classify potential security threats
- **Automated Response Mechanisms**: Configurable automated responses to common threat patterns
- **Threat Prioritization & Triage**: Intelligent sorting of threats by severity and confidence
- **Adaptive Learning**: System improves over time based on feedback and outcomes
- **Real-Time API & Dashboard**: Comprehensive API for integration with existing security tools
- **Persistent Storage**: Threats are stored in a SQLite database for historical analysis and tracking
  - Ability to track submission status of threats
  - Statistics and reporting on threat patterns
  - Retry mechanism for failed API submissions
  - Database-backed reliability even during service disruptions
- **Azure AI Integration**: Enhanced threat analysis using Azure AI services
  - OpenAI for threat classification and response generation
  - Anomaly Detector for identifying unusual behavior
  - Content Safety for scanning URLs and text
  - AI Search for threat intelligence
  - Metrics Advisor for system performance monitoring

## Setup

### Local Development

1. Create virtual environment:
```bash
python -m venv venv
```

2. Activate virtual environment:
- Windows:
```bash
.\venv\Scripts\activate
```
- Unix/MacOS:
```bash
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. Run the application:
```bash
uvicorn app.main:app --reload --port 8000
```

### Docker Deployment

1. Build and start the containers:
```bash
docker-compose up -d
```

2. Check container status:
```bash
docker-compose ps
```

3. View logs:
```bash
docker-compose logs -f web
```

4. Stop the containers:
```bash
docker-compose down
```

### Using Snort Connector with Docker

The Snort connector is included as a separate service in the Docker Compose configuration. It automatically monitors the `/app/snort_logs/alert` file inside the container, which is mapped to the `./snort_logs/alert` file in your project directory.

1. Start the Snort connector service:
```bash
docker-compose up -d snort-connector
```

2. View Snort connector logs:
```bash
docker-compose logs -f snort-connector
```

3. Test with sample alerts:
Add Snort-formatted alerts to the `./snort_logs/alert` file to trigger the connector. The connector will automatically detect changes and send the alerts to the CyberCare API.

4. Configure the connector:
You can customize the connector behavior by editing the environment variables in the `docker-compose.yml` file:
```yaml
environment:
  - SNORT_LOG_PATH=/app/snort_logs/alert
  - API_URL=http://web:8000/api/v1/threats/analyze
  - POLL_INTERVAL=5
  # Uncomment to enable batch mode
  # - BATCH_MODE=--batch --batch-size 10
  # Database configuration
  # - DB_PATH=/app/data/snort_threats.db
  # - RETRY_UNSENT=true
  # - RETRY_INTERVAL=60
  # - RETRY_LIMIT=3
```

## API Documentation

Once the application is running, you can access the interactive API documentation at:
- Swagger UI: `http://localhost:8005/docs`
- ReDoc: `http://localhost:8005/redoc`

### Key Endpoints

#### Health Check
```
GET /api/v1/health
```
Returns the health status of the application.

#### Authentication
```
POST /api/v1/auth/login
```
Authenticate and get an access token.

```
POST /api/v1/auth/register
```
Register a new user.

```
GET /api/v1/auth/me
```
Get current user information.

#### Threat Analysis
```
POST /api/v1/threats/analyze
```
Analyze a single security threat.

```
POST /api/v1/threats/batch-analyze
```
Analyze multiple security threats in background.

```
GET /api/v1/threats/status/{job_id}
```
Check the status of a batch analysis job.

```
GET /api/v1/threats/recent
```
Get recent analyzed threats.

## Monitoring & Simulation Tools

CyberCare comes with built-in tools for threat monitoring and simulation, perfect for testing and demonstrations.

### Threat Simulator

The threat simulator generates synthetic security events to test the system's detection and response capabilities.

```bash
# Generate a single threat
python tools/threat_simulator.py --url http://localhost:8005/api/v1/threats/analyze

# Generate a batch of threats
python tools/threat_simulator.py --batch --batch-url http://localhost:8005/api/v1/threats/batch-analyze --batch-size 5

# Run continuous simulation
python tools/threat_simulator.py --continuous --min-interval 5 --max-interval 15 --duration 60
```

### Snort IDS Connector

The Snort connector monitors Snort IDS alert logs and forwards detected threats to the CyberCare API.

```bash
# Monitor a Snort alert log file using polling
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --poll-interval 5

# Use file system monitoring (more efficient)
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --watch

# Process alerts in batch mode
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --batch-mode --batch-size 10

# Enable Azure AI integration for enhanced threat analysis
python tools/snort_connector.py --log-path /path/to/snort/alert --api-url http://localhost:8005/api/v1/threats/analyze --use-ai

# Specify custom database path for persistent storage
python tools/snort_connector.py --log-path /path/to/snort/alert --db-path /path/to/custom/database.db

# Configure retry for unsent alerts
python tools/snort_connector.py --log-path /path/to/snort/alert --retry-unsent --retry-interval 60 --retry-limit 3
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://postgres:postgres@db:5432/cybercare` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |
| `SECRET_KEY` | JWT secret key | `changeme` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Token expiration time | `30` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `LOG_FILE` | Log file path | `app.log` |
| `USE_AZURE_AI` | Enable Azure AI services | `False` |
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI service endpoint | - |
| `AZURE_OPENAI_KEY` | Azure OpenAI API key | - |
| `AZURE_OPENAI_DEPLOYMENT_ID` | Azure OpenAI deployment ID | - |
| `AZURE_ANOMALY_DETECTOR_ENDPOINT` | Azure Anomaly Detector endpoint | - |
| `AZURE_ANOMALY_DETECTOR_KEY` | Azure Anomaly Detector API key | - |
| `AZURE_CONTENT_SAFETY_ENDPOINT` | Azure Content Safety endpoint | - |
| `AZURE_CONTENT_SAFETY_KEY` | Azure Content Safety API key | - |
| `AZURE_SEARCH_ENDPOINT` | Azure AI Search endpoint | - |
| `AZURE_SEARCH_KEY` | Azure AI Search API key | - |
| `AZURE_SEARCH_INDEX_NAME` | Azure AI Search index name | - |
| `AZURE_METRICS_ADVISOR_ENDPOINT` | Azure Metrics Advisor endpoint | - |
| `AZURE_METRICS_ADVISOR_SUBSCRIPTION_KEY` | Azure Metrics Advisor subscription key | - |
| `AZURE_METRICS_ADVISOR_API_KEY` | Azure Metrics Advisor API key | - |

## Project Structure

```
cybercare/
├── app/
│   ├── api/
│   │   ├── deps.py             # Dependency injection
│   │   └── endpoints/
│   │       ├── auth.py         # Authentication endpoints
│   │       ├── threats.py      # Threat analysis endpoints
│   │       ├── incidents.py    # Incident management
│   │       └── analysis.py     # Analytics and reporting
│   ├── core/
│   │   ├── config.py           # Application configuration
│   │   └── security.py         # Security utilities
│   ├── db/
│   │   ├── base.py             # Database connection
│   │   └── models.py           # SQLAlchemy models
│   ├── models/
│   │   ├── ai/
│   │   │   ├── threat_classifier.py  # AI threat classification
│   │   │   └── azure/          # Azure AI services integration
│   │   │       ├── openai_service.py        # Azure OpenAI integration
│   │   │       ├── anomaly_detector.py      # Azure Anomaly Detector
│   │   │       ├── content_safety.py        # Azure Content Safety
│   │   │       ├── search_service.py        # Azure AI Search
│   │   │       ├── metrics_advisor.py       # Azure Metrics Advisor
│   │   │       └── ai_service_manager.py    # Unified AI service manager
│   │   └── domain/
│   │       ├── user.py         # User domain models
│   │       └── threat.py       # Threat domain models
│   ├── services/
│   │   ├── threat_detection.py # Threat detection service
│   │   └── response_automation.py  # Automated response
│   └── main.py                 # Application entry point
├── tests/
│   ├── conftest.py             # Test fixtures
│   ├── test_auth.py            # Authentication tests
│   └── test_threats.py         # Threat analysis tests
├── alembic/                    # Database migrations
├── docker-compose.yml          # Docker configuration
├── Dockerfile                  # Docker build instructions
├── .env.example                # Environment variables template
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation
```

## Version History

- **0.2.0** - Azure AI Integration
  - Added Azure OpenAI, Anomaly Detector, Content Safety, AI Search, and Metrics Advisor
  - Enhanced Snort connector with AI capabilities
  - Expanded database schema for AI analysis
  - Improved logging and error handling
- **0.1.0** - Initial release with core functionality
  - AI-powered threat detection
  - Basic authentication
  - Threat analysis API
  - Docker containerization

## License

This project is licensed under the MIT License - see the LICENSE file for details.
