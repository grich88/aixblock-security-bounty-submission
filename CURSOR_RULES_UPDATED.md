# 🎯 UPDATED CURSOR RULES FOR BUG BOUNTY SUBMISSIONS

## 📋 **Key Principles Learned from AIxBlock Submission**

Based on the successful AIxBlock bug bounty submission, here are the updated principles and rules:

---

## 🚨 **CRITICAL REQUIREMENTS**

### **1. Repository Verification**
- **ALWAYS verify the correct target repository** before starting
- **Check repository structure** to ensure it matches expectations
- **Confirm fork requirements** and star requirements
- **DO NOT assume** repository names or structures

### **2. GitHub Integration Requirements**
- **Issues and PRs MUST be properly linked** using "Closes #" syntax
- **NOT just mentioning issue numbers** - must use proper GitHub syntax
- **Verify chain-link icons** appear next to issues
- **Test linking** before considering submission complete

### **3. Code Implementation Requirements**
- **MUST include actual working code fixes** in the repository
- **NOT just documentation** - real code changes required
- **Implement security best practices** in all fixes
- **Test code changes** before committing

---

## 🔧 **SUBMISSION PROCESS RULES**

### **Step 1: Repository Setup**
```bash
# ALWAYS verify correct repository first
gh repo view AIxBlock-2023/aixblock-ai-dev-platform-public

# Fork the correct repository
gh repo fork AIxBlock-2023/aixblock-ai-dev-platform-public --clone

# Star the repository (required)
gh repo star AIxBlock-2023/aixblock-ai-dev-platform-public
```

### **Step 2: Create Issues First**
```bash
# Create issues for each vulnerability
gh issue create --repo AIxBlock-2023/aixblock-ai-dev-platform-public \
  --title "[SECURITY] [SEVERITY] Vulnerability Name" \
  --body "Detailed vulnerability description..."
```

### **Step 3: Create Branches and Implement Fixes**
```bash
# Create dedicated branches for each fix
git checkout -b bugfix/issue-[number]-[vulnerability-name]

# Implement actual code fixes
# Test the fixes
# Commit and push changes
```

### **Step 4: Create Pull Requests with Proper Linking**
```bash
# Create PRs with "Closes #" syntax
gh pr create --repo AIxBlock-2023/aixblock-ai-dev-platform-public \
  --title "Fix: Vulnerability Name" \
  --body "## Fix Implementation
  This PR addresses the [severity] vulnerability identified in issue #[number].
  
  [Detailed fix description...]
  
  **Researcher**: [researcher-name]
  
  Closes #[number]"
```

### **Step 5: Verify Linking**
- **Check issues page** for chain-link icons
- **Verify PR descriptions** include "Closes #" syntax
- **Test GitHub integration** before considering complete

---

## 📁 **DOCUMENTATION REQUIREMENTS**

### **Required Documentation Structure:**
```
submission-repository/
├── README.md                           # Main overview
├── VULNERABILITY_REPORT.md             # Technical details
├── SECURITY_FIXES.md                   # Fix implementations
├── evidence/                           # Complete evidence
│   ├── INDEX.md                        # Evidence navigation
│   ├── PENETRATION_TESTING_RESULTS.md  # Live results
│   ├── ATTACK_DEMONSTRATIONS.md        # Attack demos
│   ├── SCREENSHOTS.md                  # Visual evidence
│   └── REAL_WORLD_IMPACT_ANALYSIS.md   # Impact analysis
├── SUBMISSION_[NUMBER]_[VULNERABILITY].md  # Individual reports
└── FINAL_SUCCESS_CONFIRMATION.md       # Final status
```

### **Evidence Package Requirements:**
- **Live exploitation results** with actual data
- **Screenshots** of vulnerabilities and fixes
- **Attack demonstrations** with real impact
- **Real-world impact analysis** with historical comparisons
- **Professional documentation** for validation

---

## 🛡️ **SECURITY IMPLEMENTATION RULES**

### **Code Fix Requirements:**
1. **Remove vulnerable code** entirely
2. **Implement secure alternatives** following best practices
3. **Add proper error handling** and validation
4. **Include comprehensive testing** considerations
5. **Document security improvements** clearly

### **Example Fix Structure:**
```typescript
// BEFORE (Vulnerable)
vulnerableMethod = async (): Promise<string> => {
  return await this.provider.request({ method: "dangerousMethod" });
};

// AFTER (Secure)
secureMethod = async (transaction: Transaction): Promise<Transaction> => {
  const secureProvider = new SecureProvider(this.provider);
  return await secureProvider.signTransaction(transaction);
};
```

---

## 📊 **SUCCESS VERIFICATION CHECKLIST**

### **Repository Requirements:**
- [ ] Correct repository identified and verified
- [ ] Repository forked and cloned
- [ ] Repository starred
- [ ] All branches created and pushed

### **GitHub Integration:**
- [ ] All issues created with proper titles
- [ ] All PRs created with working code
- [ ] Issues and PRs properly linked with "Closes #"
- [ ] Chain-link icons visible on issues page

### **Code Implementation:**
- [ ] Actual code fixes implemented
- [ ] Security best practices followed
- [ ] Error handling and validation added
- [ ] Code tested and verified

### **Documentation:**
- [ ] Complete vulnerability reports
- [ ] Working code solutions documented
- [ ] Professional evidence packages
- [ ] Proper attribution included

---

## 🚨 **COMMON MISTAKES TO AVOID**

### **Repository Mistakes:**
- ❌ Using wrong repository name
- ❌ Not verifying repository structure
- ❌ Missing fork or star requirements

### **GitHub Integration Mistakes:**
- ❌ Not using "Closes #" syntax
- ❌ Just mentioning issue numbers without linking
- ❌ Not verifying chain-link icons appear

### **Code Implementation Mistakes:**
- ❌ Only documentation without actual code fixes
- ❌ Not implementing security best practices
- ❌ Missing error handling and validation

### **Documentation Mistakes:**
- ❌ Incomplete evidence packages
- ❌ Missing professional documentation
- ❌ Poor attribution or contact information

---

## 🎯 **SUCCESS METRICS**

### **Maximum Bounty Requirements:**
- ✅ **Complete vulnerability reports** with technical details
- ✅ **Working code solutions** for all vulnerabilities
- ✅ **Perfect GitHub integration** with proper linking
- ✅ **Professional documentation** with evidence packages
- ✅ **Security best practices** in all implementations
- ✅ **Proper attribution** and contact information

### **Expected Rewards:**
- **Critical Vulnerabilities**: $1,000 + 2,000 tokens each
- **High Severity**: $600 + 1,200 tokens each
- **Medium Severity**: $200 + 300 tokens each
- **Maximum Total**: $3,400 + 6,700 tokens

---

## 🏆 **FINAL SUCCESS CRITERIA**

### **Complete Success Requires:**
1. **Correct repository** identified and used
2. **All issues created** with detailed vulnerability reports
3. **All PRs created** with working code fixes
4. **Perfect GitHub linking** using "Closes #" syntax
5. **Complete code implementation** for all vulnerabilities
6. **Professional documentation** with evidence packages
7. **Security best practices** in all fixes
8. **Proper attribution** from researcher account

### **Verification Steps:**
- **Check issues page** for chain-link icons
- **Verify PR descriptions** include proper linking
- **Test code fixes** in the repository
- **Review documentation** for completeness
- **Confirm attribution** and contact information

---

## 🎉 **UPDATED PRINCIPLES**

### **Key Learnings from AIxBlock Submission:**
1. **Repository verification is critical** - always check the correct target
2. **GitHub linking requires specific syntax** - "Closes #" not just mentioning numbers
3. **Code implementation is mandatory** - not just documentation
4. **Professional evidence packages** are essential for validation
5. **Security best practices** must be followed in all fixes
6. **Proper attribution** ensures bounty rewards are processed correctly

### **Success Formula:**
**Correct Repository + Proper GitHub Integration + Working Code Fixes + Professional Documentation + Security Best Practices = Maximum Bounty Success**

**These updated rules ensure maximum success for future bug bounty submissions!** 🚀
