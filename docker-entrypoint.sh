#!/bin/bash
set -e

# Function to handle Snort connector mode
start_snort_connector() {
    echo "Starting Snort IDS Connector..."
    # Create snort_logs directory if it doesn't exist
    mkdir -p /app/snort_logs
    
    # Start the connector with specified parameters
    python /app/tools/snort_connector.py --log-path "$SNORT_LOG_PATH" --api-url "$API_URL" $BATCH_MODE --poll-interval "$POLL_INTERVAL"
}

# Check if we should run the Snort connector instead of the web app
if [ "$RUN_MODE" = "snort-connector" ]; then
    # Set default values if not provided
    SNORT_LOG_PATH=${SNORT_LOG_PATH:-"/app/snort_logs/alert"}
    API_URL=${API_URL:-"http://web:8000/api/v1/threats/analyze"}
    POLL_INTERVAL=${POLL_INTERVAL:-5}
    BATCH_MODE=${BATCH_MODE:-""}
    
    start_snort_connector
    exit 0
fi

echo "Waiting for database to be ready..."
MAX_TRIES=30
TRIES=0
until pg_isready -h db -U postgres -d cybercare || [ $TRIES -eq $MAX_TRIES ]; do
    TRIES=$((TRIES+1))
    echo "Waiting for database to be ready... $TRIES/$MAX_TRIES"
    sleep 2
done

if [ $TRIES -eq $MAX_TRIES ]; then
    echo "Database connection failed after $MAX_TRIES attempts"
    exit 1
fi

echo "Database is ready!"

echo "Waiting for Redis to be ready..."
MAX_TRIES=30
TRIES=0
until redis-cli -h redis ping | grep "PONG" || [ $TRIES -eq $MAX_TRIES ]; do
    TRIES=$((TRIES+1))
    echo "Waiting for Redis to be ready... $TRIES/$MAX_TRIES"
    sleep 2
done

if [ $TRIES -eq $MAX_TRIES ]; then
    echo "Redis connection failed after $MAX_TRIES attempts"
    exit 1
fi

echo "Redis is ready!"

# Check if migrations directory exists
if [ -d "/app/alembic/versions" ]; then
    # Apply database migrations with alembic
    echo "Applying database migrations..."
    alembic upgrade head
else
    echo "Migrations directory not found, skipping migrations"
    echo "Creating initial migrations directory..."
    mkdir -p /app/alembic/versions
fi

# Start the application with Uvicorn
echo "Starting the application..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
