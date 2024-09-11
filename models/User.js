const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    empId: { type: String, required: true, unique: true },
    email: { type: String },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['admin', 'medical_rep'] }
});

module.exports = mongoose.model('User', userSchema);
