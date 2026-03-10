const { FortressCli, getFortressVersion } = require('../index.js');

const test = async () => {
  console.log('🧪 Testing Fortress NAPI bindings...');
  
  try {
    // Test version function
    console.log('Testing getFortressVersion...');
    const version = getFortressVersion();
    console.log('✅ Version:', version);
    
    // Test CLI class
    console.log('Testing FortressCli class...');
    const cli = new FortressCli();
    console.log('✅ CLI instance created');
    
    // Test version command
    console.log('Testing CLI version command...');
    const result = await cli.version();
    console.log('✅ CLI version result:', result);
    
    // Test help command
    console.log('Testing CLI help command...');
    const help = await cli.help();
    console.log('✅ CLI help works (length:', help.length, ')');
    
    console.log('🎉 All tests passed!');
  } catch (error) {
    console.error('❌ Test failed:', error);
    process.exit(1);
  }
};

test();
