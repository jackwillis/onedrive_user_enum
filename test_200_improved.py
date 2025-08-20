#!/usr/bin/env python3
"""
Improved test of 200 random samples with better pattern matching
Uses the new PatternVerifier class for cleaner control flow
"""

import random
import json
import time
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import functions from main script
from onedrive_enum import (
    get_tenant_id, 
    get_tenant_brand_name,
    TenantDiscovery
)

def load_stratified_sample():
    """Load domains from stratified sample files"""
    domains = []
    
    # Distribution for 200 samples (proportional to original)
    distribution = {
        'tier1_enterprise.txt': 20,      # 10% - Top 1K
        'tier2_upper_mid.txt': 40,       # 20% - 1K-5K  
        'tier3_mid_market.txt': 80,      # 40% - 5K-25K
        'tier4_lower_mid.txt': 40,       # 20% - 25K-100K
        'tier5_long_tail.txt': 20        # 10% - 100K-1M
    }
    
    for filename, count in distribution.items():
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                lines = [line.strip() for line in f.readlines() if line.strip()]
                # Random sample from this tier
                sample = random.sample(lines, min(count, len(lines)))
                domains.extend(sample)
                print(f"Loaded {len(sample)} domains from {filename}")
        else:
            print(f"Warning: {filename} not found")
    
    # Shuffle the combined list
    random.shuffle(domains)
    return domains[:200]  # Ensure we have exactly 200

def test_domain_improved(domain, verbose=False):
    """Test pattern discovery for a domain using improved verifier"""
    result = {
        'domain': domain,
        'tenant_id': None,
        'brand_name': None,
        'patterns_tested': [],
        'pattern_found': None,
        'status': None,
        'discovery_method': None
    }
    
    try:
        # Get tenant info
        tenant_id = get_tenant_id(domain)
        brand_name = get_tenant_brand_name(domain)
        
        result['tenant_id'] = tenant_id
        result['brand_name'] = brand_name
        
        if not (tenant_id or brand_name):
            result['discovery_method'] = 'No Azure AD'
            return result
        
        # Use TenantDiscovery for everything
        discovery = TenantDiscovery(verbose=verbose)
        patterns = discovery._generate_patterns(domain, brand_name)
        result['patterns_tested'] = patterns
        verification_results = discovery._test_all_patterns(patterns, domain)
        
        if verification_results:
            result['pattern_found'] = verification_results[0]
            result['status'] = verification_results[1]
            
            if verification_results[1] == discovery.VERIFIED:
                result['discovery_method'] = 'Pattern Match (HTTP Verified)'
            elif verification_results[1] == discovery.TIMEOUT:
                result['discovery_method'] = 'Pattern Match (DNS Timeout)'
            else:
                result['discovery_method'] = f'Pattern Match ({verification_results[1]})'
        else:
            result['discovery_method'] = 'Azure AD but no pattern found'
    
    except Exception as e:
        result['error'] = str(e)
        result['discovery_method'] = 'Error'
    
    return result

def main():
    print("="*80)
    print("Improved Testing of 200 Random Samples")
    print("Using new TenantDiscovery with cleaner control flow")
    print("="*80)
    
    # Set random seed for reproducibility
    random.seed(42)
    
    # Check if we have progress file
    progress_file = "test_200_improved_progress.json"
    results_file = "test_200_improved_results.json"
    
    if os.path.exists(progress_file):
        print("\nFound progress file, resuming...")
        with open(progress_file, 'r') as f:
            progress_data = json.load(f)
            domains = progress_data['remaining_domains']
            results = progress_data['results']
            print(f"Resuming with {len(domains)} domains remaining")
    else:
        # Load domains
        print("\nLoading stratified sample...")
        domains = load_stratified_sample()
        results = []
        print(f"Total domains loaded: {len(domains)}")
    
    # Test each domain
    start_time = time.time()
    total_domains = len(domains) + len(results)
    
    print("\nTesting pattern discovery with improved verifier...")
    print("-"*80)
    
    while domains:
        domain = domains.pop(0)
        i = len(results) + 1
        
        if i % 10 == 0:
            elapsed = time.time() - start_time
            rate = len(results) / elapsed if elapsed > 0 else 1
            remaining = len(domains) / rate if rate > 0 else 0
            print(f"Progress: {i}/{total_domains} ({100*i/total_domains:.1f}%) - "
                  f"Est. remaining: {remaining:.0f}s")
            
            # Save progress every 10 domains
            with open(progress_file, 'w') as f:
                json.dump({
                    'remaining_domains': domains,
                    'results': results
                }, f)
        
        result = test_domain_improved(domain, verbose=False)
        results.append(result)
        
        # Brief output for each domain
        if result['pattern_found']:
            status = result['status']
            status_icon = "✓" if status == 'verified' else "◐" if status == 'timeout' else "?"
            print(f"{status_icon} {i:3}. {domain:40} -> {result['pattern_found']:20} ({status})")
        elif result['tenant_id']:
            print(f"? {i:3}. {domain:40} -> Azure AD but no pattern")
        else:
            print(f"✗ {i:3}. {domain:40} -> No Azure AD")
        
        # Rate limiting
        time.sleep(0.3)
    
    # Save all results
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    # Clean up progress file
    if os.path.exists(progress_file):
        os.remove(progress_file)
    
    print(f"\n{'='*80}")
    print("SUMMARY")
    print("="*80)
    
    # Calculate statistics
    total = len(results)
    with_azure = sum(1 for r in results if r.get('tenant_id'))
    with_pattern = sum(1 for r in results if r.get('pattern_found'))
    http_verified = sum(1 for r in results if r.get('status') == 'verified')
    dns_timeout = sum(1 for r in results if r.get('status') == 'timeout')
    no_azure = sum(1 for r in results if r.get('discovery_method') == 'No Azure AD')
    azure_no_pattern = sum(1 for r in results if r.get('tenant_id') and not r.get('pattern_found'))
    
    print(f"Total domains tested: {total}")
    print(f"Domains with Azure AD: {with_azure} ({100*with_azure/total:.1f}%)")
    print(f"Domains with pattern found: {with_pattern} ({100*with_pattern/total:.1f}%)")
    print(f"  - HTTP verified: {http_verified} ({100*http_verified/total:.1f}%)")
    print(f"  - DNS timeout: {dns_timeout} ({100*dns_timeout/total:.1f}%)")
    print(f"Domains without Azure AD: {no_azure} ({100*no_azure/total:.1f}%)")
    print(f"Azure AD but no pattern: {azure_no_pattern} ({100*azure_no_pattern/total:.1f}%)")
    
    if with_azure > 0:
        print(f"\nPattern discovery success rate (for Azure AD domains): "
              f"{100*with_pattern/with_azure:.1f}%")
        if with_pattern > 0:
            print(f"HTTP verification rate (for patterns found): "
                  f"{100*http_verified/with_pattern:.1f}%")
    
    # Select 20 for manual verification
    print(f"\n{'='*80}")
    print("20 DOMAINS FOR MANUAL VERIFICATION")
    print("="*80)
    print("\nSelecting diverse sample for verification...")
    
    verification_sample = []
    
    # Get different categories
    http_verified_list = [r for r in results if r.get('status') == 'verified']
    dns_timeout_list = [r for r in results if r.get('status') == 'timeout']
    azure_no_pattern_list = [r for r in results if r.get('tenant_id') and not r.get('pattern_found')]
    
    # Take proportional samples
    if http_verified_list:
        verification_sample.extend(random.sample(http_verified_list, min(10, len(http_verified_list))))
    if dns_timeout_list:
        verification_sample.extend(random.sample(dns_timeout_list, min(5, len(dns_timeout_list))))
    if azure_no_pattern_list:
        verification_sample.extend(random.sample(azure_no_pattern_list, min(5, len(azure_no_pattern_list))))
    
    # Ensure we have 20
    verification_sample = verification_sample[:20]
    
    # Create verification template
    verification_data = []
    print("\nDomains selected for manual verification:")
    print("-"*80)
    for i, result in enumerate(verification_sample, 1):
        verification_data.append({
            'number': i,
            'domain': result['domain'],
            'our_pattern': result.get('pattern_found', 'NOT_FOUND'),
            'status': result.get('status', 'N/A'),
            'tenant_id': result.get('tenant_id'),
            'brand_name': result.get('brand_name'),
            'actual_tenant': '???'  # To be filled in manually
        })
        
        print(f"{i:2}. Domain: {result['domain']}")
        print(f"    Our result: {result.get('pattern_found', 'NOT_FOUND')}")
        print(f"    Status: {result.get('status', 'N/A')}")
        if result.get('tenant_id'):
            print(f"    Tenant ID: {result['tenant_id'][:8]}...")
        if result.get('brand_name'):
            print(f"    Brand: {result['brand_name']}")
        print()
    
    # Save verification template
    with open('manual_verification_improved.json', 'w') as f:
        json.dump(verification_data, f, indent=2)
    
    print(f"\nVerification template saved to: manual_verification_improved.json")
    print(f"Full results saved to: {results_file}")
    print(f"\nPlease fill in the 'actual_tenant' field for each domain in manual_verification_improved.json")
    print("\nThen run: python3 calculate_accuracy.py manual_verification_improved.json")

if __name__ == "__main__":
    main()