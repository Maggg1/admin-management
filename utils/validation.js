const { validationResult } = require('express-validator');

const handleValidation = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // Extract only the essential error information
    const errorMessages = errors.array().map(error => ({
      field: error.path,
      message: error.msg,
      value: error.value
    }));
    return res.status(400).json({ 
      success: false,
      message: 'Validation failed',
      errors: errorMessages 
    });
  }
  next();
};

module.exports = handleValidation;
