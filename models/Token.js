const mongoose     = require('mongoose');
const Schema       = mongoose.Schema;

const TokenSchema   = new Schema({
    id: String,
    token: String,
    expireAt: {
        type: Date,
        required: true,
        default: function() {
            // 10 minutes from now
            return new Date(Date.now() + 600000);
        }
    },
})

module.exports = mongoose.model('Token', TokenSchema);