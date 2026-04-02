import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate } from 'k6/metrics';

// Custom metrics
let errorRate = new Rate('errors');

// Test configuration
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const TEST_DURATION = __ENV.TEST_DURATION || '2m';
const VUS = __ENV.VUS || 50;

export let options = {
  stages: [
    { duration: '30s', target: 10 },   // Ramp up to 10 users
    { duration: '1m', target: 50 },    // Stay at 50 users
    { duration: '30s', target: 100 },  // Ramp up to 100 users
    { duration: '1m', target: 100 },   // Stay at 100 users
    { duration: '30s', target: 0 },    // Ramp down
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
    http_req_failed: ['rate<0.1'],    // Error rate should be less than 10%
    checks: ['rate>0.9'],            // 90% of checks should pass
  },
};

export function setup() {
  console.log(`Starting load test against ${BASE_URL}`);
  console.log(`Test duration: ${TEST_DURATION}`);
  console.log(`Virtual users: ${VUS}`);
}

// Basic health check test
export function healthCheck() {
  let response = http.get(`${BASE_URL}/health`);
  
  let checkResult = check(response, {
    'health check status is 200': (r) => r.status === 200,
    'health check response time < 100ms': (r) => r.timings.duration < 100,
    'health check contains status': (r) => r.json().hasOwnProperty('status'),
  });

  if (!checkResult) {
    errorRate.add(1);
  }

  sleep(1);
}

// GraphQL query test
export function graphqlQuery() {
  const query = `
    query {
      version
      databases {
        id
        name
        created_at
      }
    }
  `;

  let params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  let response = http.post(`${BASE_URL}/graphql`, JSON.stringify({ query }), params);

  let checkResult = check(response, {
    'GraphQL query status is 200': (r) => r.status === 200,
    'GraphQL query response time < 200ms': (r) => r.timings.duration < 200,
    'GraphQL query has data': (r) => r.json('data') !== null,
    'GraphQL query no errors': (r) => r.json('errors') === undefined,
  });

  if (!checkResult) {
    errorRate.add(1);
  }

  sleep(1);
}

// GraphQL mutation test
export function graphqlMutation() {
  const mutation = `
    mutation {
      createDatabase(input: {
        name: "test-db-${Math.random().toString(36).substr(2, 9)}"
        description: "Test database for load testing"
        tags: ["load-test", "performance"]
      }) {
        id
        name
        created_at
      }
    }
  `;

  let params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  let response = http.post(`${BASE_URL}/graphql`, JSON.stringify({ query: mutation }), params);

  let checkResult = check(response, {
    'GraphQL mutation status is 200': (r) => r.status === 200,
    'GraphQL mutation response time < 500ms': (r) => r.timings.duration < 500,
    'GraphQL mutation has data': (r) => r.json('data') !== null,
    'GraphQL mutation no errors': (r) => r.json('errors') === undefined,
  });

  if (!checkResult) {
    errorRate.add(1);
  }

  sleep(2);
}

// Data storage test
export function dataStorage() {
  const data = {
    key: `test-key-${Math.random().toString(36).substr(2, 9)}`,
    data: btoa(`Load test data at ${new Date().toISOString()}`),
    algorithm: "aes256",
    metadata: {
      source: "load-test",
      timestamp: new Date().toISOString(),
      test_id: Math.random().toString(36)
    }
  };

  let params = {
    headers: {
      'Content-Type': 'application/json',
    },
  };

  let response = http.post(`${BASE_URL}/api/v1/data`, JSON.stringify(data), params);

  let checkResult = check(response, {
    'Data storage status is 200': (r) => r.status === 200,
    'Data storage response time < 300ms': (r) => r.timings.duration < 300,
    'Data storage has response': (r) => r.json('success') === true,
  });

  if (!checkResult) {
    errorRate.add(1);
  }

  sleep(1);
}

// Data retrieval test
export function dataRetrieval() {
  const key = 'test-key-for-retrieval';
  
  let response = http.get(`${BASE_URL}/api/v1/data/${key}`);

  let checkResult = check(response, {
    'Data retrieval status is 200 or 404': (r) => r.status === 200 || r.status === 404,
    'Data retrieval response time < 150ms': (r) => r.timings.duration < 150,
  });

  if (!checkResult) {
    errorRate.add(1);
  }

  sleep(1);
}

// Security endpoints test
export function securityEndpoints() {
  // Test security health endpoint
  let response = http.get(`${BASE_URL}/health/security`);

  let checkResult = check(response, {
    'Security health status is 200': (r) => r.status === 200,
    'Security health response time < 200ms': (r) => r.timings.duration < 200,
    'Security health has status': (r) => r.json().hasOwnProperty('status'),
  });

  // Test security events endpoint
  response = http.get(`${BASE_URL}/security/events`);

  check(response, {
    'Security events status is 200': (r) => r.status === 200,
    'Security events response time < 300ms': (r) => r.timings.duration < 300,
    'Security events has events array': (r) => r.json().hasOwnProperty('events'),
  });

  sleep(2);
}

// Metrics endpoint test
export function metricsEndpoint() {
  let response = http.get(`${BASE_URL}/metrics`);

  check(response, {
    'Metrics status is 200': (r) => r.status === 200,
    'Metrics response time < 100ms': (r) => r.timings.duration < 100,
    'Metrics contains prometheus data': (r) => r.body.includes('fortress_'),
  });

  sleep(1);
}

// Main test function - randomly select different test types
export default function () {
  const tests = [
    healthCheck,
    graphqlQuery,
    graphqlMutation,
    dataStorage,
    dataRetrieval,
    securityEndpoints,
    metricsEndpoint,
  ];

  // Randomly select a test to run
  const randomTest = tests[Math.floor(Math.random() * tests.length)];
  randomTest();
}

export function teardown(data) {
  console.log('Load test completed');
  console.log(`Error rate: ${errorRate.rate * 100}%`);
}
