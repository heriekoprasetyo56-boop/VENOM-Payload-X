const premiumList = require('../premium.json'); // Import dari luar folder premium

const isPremium = (userId) => {
  return premiumList.includes(userId);
};

module.exports = { isPremium };
