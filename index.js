var Resource = require('deployd/lib/resource')
var util = require('util');
var internalClient = require('deployd/lib/internal-client')

var DPD_HASHING_SALT = process.env.DPD_HASHING_SALT;


function Hash(name, options) {
	Resource.apply(this, arguments);
}
util.inherits(Hash, Resource);
module.exports = Hash;

Hash.prototype.clientGeneration = true;
Hash.prototype.handle = function (ctx, next) {

	// Only allow POST
    if(ctx.req && ctx.req.method !== 'POST') 
    	return next();

    // Validate
    var body = ctx.req.body || {}
    if(!body || !body.k){
    	return next();
    }

    var hash = hash(body.k, DPD_HASHING_SALT);
    ctx.done(null, hash)
}

var crypto = require("crypto");
function hash(password, salt){
    return crypto.createHmac('sha256', salt).update(password).digest('hex');    
}
