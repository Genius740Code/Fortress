#!/bin/bash

# Fortress Docker Helper Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Fortress Docker Helper Script"
    echo ""
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  build           Build all Docker images"
    echo "  build-server    Build only server image"
    echo "  build-cli       Build only CLI image"
    echo "  up              Start production stack"
    echo "  up-dev          Start development stack"
    echo "  down            Stop and remove containers"
    echo "  logs            Show logs for services"
    echo "  shell           Get shell in container"
    echo "  clean           Clean up containers and images"
    echo "  status          Show container status"
    echo ""
    echo "Options:"
    echo "  --profile PROFILE    Docker Compose profile (postgres, redis, monitoring)"
    echo "  --service SERVICE   Specific service for logs/shell"
    echo ""
    echo "Examples:"
    echo "  $0 build"
    echo "  $0 up --profile postgres,redis"
    echo "  $0 logs --service fortress-server"
    echo "  $0 shell --service fortress-cli"
}

# Function to build images
build_images() {
    local service=$1
    print_status "Building Docker images..."
    
    case $service in
        "server")
            docker build -t fortress-server:latest -f crates/fortress-server/Dockerfile .
            ;;
        "cli")
            docker build -t fortress-cli:latest -f crates/fortress-cli/Dockerfile .
            ;;
        *)
            docker build -t fortress:latest .
            docker build -t fortress-server:latest -f crates/fortress-server/Dockerfile .
            docker build -t fortress-cli:latest -f crates/fortress-cli/Dockerfile .
            ;;
    esac
}

# Function to start services
start_services() {
    local compose_file=$1
    local profile=$2
    
    print_status "Starting Fortress services..."
    
    if [ -n "$profile" ]; then
        docker-compose -f docker/$compose_file --profile $profile up -d
    else
        docker-compose -f docker/$compose_file up -d
    fi
}

# Function to stop services
stop_services() {
    print_status "Stopping Fortress services..."
    docker-compose -f docker/docker-compose.yml down
}

# Function to show logs
show_logs() {
    local service=$1
    if [ -n "$service" ]; then
        docker-compose -f docker/docker-compose.yml logs -f $service
    else
        docker-compose -f docker/docker-compose.yml logs -f
    fi
}

# Function to get shell
get_shell() {
    local service=$1
    if [ -z "$service" ]; then
        service="fortress-server"
    fi
    
    print_status "Getting shell in $service container..."
    docker-compose -f docker/docker-compose.yml exec $service /bin/bash
}

# Function to clean up
cleanup() {
    print_status "Cleaning up Docker resources..."
    
    # Stop and remove containers
    docker-compose -f docker/docker-compose.yml down -v --remove-orphans
    
    # Remove images
    docker rmi fortress:latest fortress-server:latest fortress-cli:latest 2>/dev/null || true
    
    # Remove unused volumes
    docker volume prune -f
    
    # Remove unused networks
    docker network prune -f
}

# Function to show status
show_status() {
    print_status "Fortress container status:"
    docker-compose -f docker/docker-compose.yml ps
}

# Parse command line arguments
COMMAND=""
SERVICE=""
PROFILE=""

while [[ $# -gt 0 ]]; do
    case $1 in
        build|build-server|build-cli|up|up-dev|down|logs|shell|clean|status)
            COMMAND="$1"
            shift
            ;;
        --service)
            SERVICE="$2"
            shift 2
            ;;
        --profile)
            PROFILE="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Execute command
case $COMMAND in
    build)
        build_images
        ;;
    build-server)
        build_images "server"
        ;;
    build-cli)
        build_images "cli"
        ;;
    up)
        start_services "docker-compose.yml" "$PROFILE"
        ;;
    up-dev)
        start_services "docker-compose.dev.yml"
        ;;
    down)
        stop_services
        ;;
    logs)
        show_logs "$SERVICE"
        ;;
    shell)
        get_shell "$SERVICE"
        ;;
    clean)
        cleanup
        ;;
    status)
        show_status
        ;;
    "")
        print_error "No command specified"
        show_usage
        exit 1
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac
