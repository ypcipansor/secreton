#!/bin/bash

echo "🚀 Secreton Test Validation - Quick Test Runner"
echo "=============================================="

# Test the specific fixes we implemented
echo "📋 Testing individual components..."

echo "1. Testing audit risk calculator..."
cargo test --package secreton-core test_risk_calculator

echo "2. Testing version parsing..."  
cargo test --package secreton-core test_version_parsing

echo "3. Testing compliance governance..."
cargo test --package secreton-core test_report_generation

echo "4. Testing entropy augmentation..."
cargo test --package secreton-core test_entropy_engine_basic_functionality

echo "5. Testing quantum crypto encryption..."
cargo test --package secreton-core test_encryption_decryption

echo "6. Testing quantum crypto signing..."
cargo test --package secreton-core test_signing_verification

echo ""
echo "🎯 Running complete core test suite..."
cargo test --package secreton-core

echo ""
echo "✅ Test validation complete!"