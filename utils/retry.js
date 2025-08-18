'use strict';

/**
 * Retry utility for async operations
 * @param {Function} operation - The async operation to retry
 * @param {Object} options - Retry options
 * @param {number} options.maxRetries - Maximum number of retries
 * @param {number} options.delay - Delay between retries in milliseconds
 * @param {Function} options.shouldRetry - Function to determine if should retry
 * @returns {Promise<any>} - Result of the operation
 */
async function retry(operation, options = {}) {
  const {
    maxRetries = 3,
    delay = 1000,
    shouldRetry = () => true,
    backoff = 2,
    maxDelay = 30000
  } = options;

  let lastError;
  let currentDelay = delay;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const result = await operation();
      return result;
    } catch (error) {
      lastError = error;

      if (attempt === maxRetries) {
        throw new Error(`Operation failed after ${maxRetries + 1} attempts: ${error.message}`);
      }

      if (!shouldRetry(error)) {
        throw error;
      }

      console.warn(`Attempt ${attempt + 1} failed: ${error.message}. Retrying in ${currentDelay}ms...`);
      
      await new Promise(resolve => setTimeout(resolve, currentDelay));
      
      // Exponential backoff
      currentDelay = Math.min(currentDelay * backoff, maxDelay);
    }
  }

  throw lastError;
}

/**
 * Retry with specific error handling for database operations
 * @param {Function} operation - Database operation
 * @param {Object} options - Retry options
 * @returns {Promise<any>}
 */
async function retryDatabaseOperation(operation, options = {}) {
  const dbOptions = {
    maxRetries: 5,
    delay: 1000,
    shouldRetry: (error) => {
      // Retry on connection errors, timeouts, but not validation errors
      const retryableErrors = [
        'ECONNREFUSED',
        'ENOTFOUND',
        'ETIMEDOUT',
        'MongoNetworkError',
        'MongoServerSelectionError'
      ];
      
      return retryableErrors.some(errType => 
        error.message?.includes(errType) || error.name?.includes(errType)
      );
    },
    ...options
  };

  return retry(operation, dbOptions);
}

/**
 * Retry with specific error handling for external API calls
 * @param {Function} operation - API call operation
 * @param {Object} options - Retry options
 * @returns {Promise<any>}
 */
async function retryApiCall(operation, options = {}) {
  const apiOptions = {
    maxRetries: 3,
    delay: 1000,
    shouldRetry: (error) => {
      // Retry on 5xx errors, network errors, but not 4xx errors
      const statusCode = error.response?.status;
      if (statusCode) {
        return statusCode >= 500 || statusCode === 429;
      }
      
      // Retry on network errors
      return error.code === 'ECONNREFUSED' || 
             error.code === 'ETIMEDOUT' || 
             error.code === 'ENOTFOUND';
    },
    ...options
  };

  return retry(operation, apiOptions);
}

module.exports = {
  retry,
  retryDatabaseOperation,
  retryApiCall
};
