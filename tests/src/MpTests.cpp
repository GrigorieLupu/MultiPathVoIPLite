#include "MpTests.h"
#include "MpTestsBuddy.h"
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

MpTests::MpTests() {

	testBuddy = new MpTestsBuddy();
	testSuiteList.push_back(testBuddy->testSuite);

	testAutoResendEngine = new MpTestAutoResendEngine();
	testSuiteList.push_back(testAutoResendEngine->testSuite);
}

void MpTests::Run() {
    int failedTests = 0;
    
    for (std::vector<MpTestSuiteData*>::iterator it = testSuiteList.begin();
            it != testSuiteList.end(); ++it) {
        
        MpTestSuiteData* suiteData = (MpTestSuiteData*) (*it);
        
        std::cout << "*** " << suiteData->testSuiteName.c_str() << " ***" << std::endl;
        
        // Rulează fiecare suită de teste într-un proces separat
        pid_t pid = fork();
        
        if (pid == 0) {
            // Proces copil - rulează testele
            int testNumber = 1;
            int localFailedTests = 0;
            
            for (std::vector<MpTestData>::iterator it2 = (suiteData->testsList).begin();
                    it2 != (suiteData->testsList).end(); ++it2) {
                
                std::cout << testNumber++ << "." << (*it2).testName.c_str() << "...";
                
                int testResult = (*it2).testFunction();
                
                if (testResult == 0) {
                    std::cout << "OK" << std::endl;
                } else {
                    std::cout << "FAILED!" << std::endl;
                    localFailedTests++;
                }
            }
            
            exit(localFailedTests); // Ieșire din procesul copil
        } else if (pid > 0) {
            // Proces părinte - așteaptă procesul copil
            int status;
            waitpid(pid, &status, 0);
            
            if (WIFEXITED(status)) {
                failedTests += WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                std::cout << "Test suite crashed with signal " << WTERMSIG(status) << std::endl;
                failedTests++;
            }
        } else {
            // Eroare la fork
            std::cout << "Failed to fork process for test suite" << std::endl;
            failedTests++;
        }
        
        std::cout << std::endl;
    }
    
    if (failedTests == 0) {
        std::cout << "ALL TESTS PASSED!" << std::endl;
    } else {
        std::cout << "TESTS FAILED: " << failedTests << std::endl;
    }
}

MpTests::~MpTests() {
}

