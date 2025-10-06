#!/usr/bin/env node

/**
 * Frontend Smoke Test Script
 * Tests key DOM elements and functionality across all pages
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

// Test configuration
const BASE_URL = 'http://localhost:5000';
const SCREENSHOT_DIR = './screenshots';

// Ensure screenshot directory exists
if (!fs.existsSync(SCREENSHOT_DIR)) {
    fs.mkdirSync(SCREENSHOT_DIR);
}

// Test pages and their expected elements
const TEST_PAGES = [
    {
        name: 'Home',
        url: '/',
        selectors: ['.navbar', '.main-content', '.footer'],
        description: 'Landing page with navigation'
    },
    {
        name: 'Login',
        url: '/login',
        selectors: ['form', 'input[type="email"]', 'input[type="password"]', '.btn'],
        description: 'Login form functionality'
    },
    {
        name: 'Dashboard',
        url: '/calculatentrade_journal/dashboard',
        selectors: ['.container', '.stats-card', '.page-title'],
        description: 'Main dashboard with stats',
        requiresAuth: true
    },
    {
        name: 'Trades Journal',
        url: '/calculatentrade_journal/trades',
        selectors: ['#trades-table', '.top-nav', '#menu_toggle', '.broker-section'],
        description: 'Trades table with sidebar toggle',
        requiresAuth: true
    },
    {
        name: 'Trade Form',
        url: '/calculatentrade_journal/trade_form',
        selectors: ['form', 'input', 'select', '.btn-primary'],
        description: 'Trade entry form',
        requiresAuth: true
    }
];

// JavaScript functionality tests
const JS_TESTS = [
    {
        name: 'Sidebar Toggle',
        test: async (page) => {
            const toggle = await page.$('#menu_toggle');
            if (toggle) {
                await toggle.click();
                await page.waitForTimeout(500);
                return true;
            }
            return false;
        }
    },
    {
        name: 'DataTable Initialization',
        test: async (page) => {
            return await page.evaluate(() => {
                return typeof $.fn.DataTable !== 'undefined' && $('#trades-table').length > 0;
            });
        }
    },
    {
        name: 'Bootstrap Components',
        test: async (page) => {
            return await page.evaluate(() => {
                return typeof bootstrap !== 'undefined' || typeof $ !== 'undefined';
            });
        }
    }
];

async function runTests() {
    console.log('🚀 Starting Frontend Smoke Tests...\n');
    
    const browser = await puppeteer.launch({ 
        headless: false, // Set to true for CI
        defaultViewport: { width: 1200, height: 800 }
    });
    
    const page = await browser.newPage();
    
    // Enable console logging
    page.on('console', msg => {
        if (msg.type() === 'error') {
            console.log('❌ Console Error:', msg.text());
        }
    });
    
    let passedTests = 0;
    let totalTests = 0;
    const results = [];
    
    try {
        // Test each page
        for (const testPage of TEST_PAGES) {
            console.log(`📄 Testing: ${testPage.name}`);
            totalTests++;
            
            try {
                // Navigate to page
                const response = await page.goto(BASE_URL + testPage.url, { 
                    waitUntil: 'networkidle2',
                    timeout: 10000 
                });
                
                if (!response.ok() && response.status() !== 302) {
                    throw new Error(`HTTP ${response.status()}`);
                }
                
                // Wait for page to load
                await page.waitForTimeout(2000);
                
                // Take screenshot
                const screenshotPath = path.join(SCREENSHOT_DIR, `${testPage.name.toLowerCase().replace(/\s+/g, '_')}.png`);
                await page.screenshot({ path: screenshotPath, fullPage: true });
                
                // Test selectors
                const selectorResults = [];
                for (const selector of testPage.selectors) {
                    const element = await page.$(selector);
                    selectorResults.push({
                        selector,
                        found: !!element
                    });
                }
                
                const allSelectorsFound = selectorResults.every(r => r.found);
                
                if (allSelectorsFound) {
                    console.log(`✅ ${testPage.name}: All elements found`);
                    passedTests++;
                } else {
                    console.log(`❌ ${testPage.name}: Missing elements`);
                    selectorResults.filter(r => !r.found).forEach(r => {
                        console.log(`   - Missing: ${r.selector}`);
                    });
                }
                
                results.push({
                    page: testPage.name,
                    url: testPage.url,
                    passed: allSelectorsFound,
                    selectors: selectorResults,
                    screenshot: screenshotPath
                });
                
            } catch (error) {
                console.log(`❌ ${testPage.name}: ${error.message}`);
                results.push({
                    page: testPage.name,
                    url: testPage.url,
                    passed: false,
                    error: error.message
                });
            }
            
            console.log('');
        }
        
        // Test JavaScript functionality on trades page
        console.log('🔧 Testing JavaScript Functionality...');
        try {
            await page.goto(BASE_URL + '/calculatentrade_journal/trades', { 
                waitUntil: 'networkidle2' 
            });
            
            for (const jsTest of JS_TESTS) {
                totalTests++;
                try {
                    const result = await jsTest.test(page);
                    if (result) {
                        console.log(`✅ ${jsTest.name}: Working`);
                        passedTests++;
                    } else {
                        console.log(`❌ ${jsTest.name}: Failed`);
                    }
                } catch (error) {
                    console.log(`❌ ${jsTest.name}: ${error.message}`);
                }
            }
        } catch (error) {
            console.log(`❌ JavaScript tests failed: ${error.message}`);
        }
        
    } finally {
        await browser.close();
    }
    
    // Generate report
    console.log('\n📊 Test Results Summary:');
    console.log(`Passed: ${passedTests}/${totalTests}`);
    console.log(`Success Rate: ${((passedTests/totalTests) * 100).toFixed(1)}%`);
    
    // Save detailed report
    const report = {
        timestamp: new Date().toISOString(),
        summary: {
            total: totalTests,
            passed: passedTests,
            failed: totalTests - passedTests,
            successRate: ((passedTests/totalTests) * 100).toFixed(1) + '%'
        },
        results
    };
    
    fs.writeFileSync('./test_report.json', JSON.stringify(report, null, 2));
    console.log('\n📄 Detailed report saved to: test_report.json');
    console.log('📸 Screenshots saved to: ./screenshots/');
    
    return passedTests === totalTests;
}

// Run tests if called directly
if (require.main === module) {
    runTests().then(success => {
        process.exit(success ? 0 : 1);
    }).catch(error => {
        console.error('Test runner failed:', error);
        process.exit(1);
    });
}

module.exports = { runTests };