const { getDatabase } = require('../src/database/connection');
const { seedDatabase } = require('../src/database/seed');

try {
  const db = getDatabase();
  seedDatabase(db);
  console.log('Database initialized and seeded successfully.');
  process.exit(0);
} catch (error) {
  console.error('Error during seeding:', error);
  process.exit(1);
}
