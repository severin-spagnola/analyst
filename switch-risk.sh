#!/bin/bash

# Stop and remove all containers
echo "🛑 Stopping all containers..."
docker stop $(docker ps -aq) 2>/dev/null
docker rm $(docker ps -aq) 2>/dev/null

# Start based on argument
if [ "$1" == "low" ]; then
    echo "🟢 Starting LOW RISK environment..."
    docker-compose -f docker-compose-low-risk.yml up -d
elif [ "$1" == "high" ]; then
    echo "🔴 Starting HIGH RISK environment..."
    docker-compose -f docker-compose-high-risk.yml up -d
else
    echo "🟡 Starting NORMAL RISK environment..."
    docker-compose up -d
fi

# Wait a bit
sleep 3

# Show what's running
echo ""
echo "📊 Running containers:"
docker ps --format "table {{.Names}}\t{{.Ports}}\t{{.Status}}"