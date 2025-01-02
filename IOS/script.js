// Interceptor.attach(Module.findExportByName(null, "getpid"), {
//     onEnter: function (args) {
//         // getpid 함수가 호출되었을 때의 동작 (필요하다면 활성화)
//         // console.log("[*] getpid 함수가 호출되었습니다.");
//     },
//     onLeave: function (retval) {
//         // 반환 값을 1515로 설정
//         // retval.replace(1515);

//         // 10진수로 변환하여 출력 (필요할 경우)
//         console.log("[*] getpid가 반환하는 값 (10진수): " + retval.toInt32());
//     }
// });


// const svcInstructionPattern = "01 10 00 D4";
// const nopInstructionBytes = [0x1F, 0x20, 0x03, 0xD5];
// const failedAddresses = []; // 보호 설정 실패 주소를 저장할 배열

// function patchSvcToNop() {
//     console.log("[*] SVC #0x80 패턴을 NOP로 변경합니다...");
//     Memory.scan(Process.enumerateModules()[0].base, Process.enumerateModules()[0].size, svcInstructionPattern, {
//         onMatch: function (address, size) {
//             console.log("[*] SVC #0x80이 발견됨:", address);
//             try {
//                 // 메모리에 쓰기 권한 부여
//                 if (!Memory.protect(address, size, 'rwx')) {
//                     console.log("[!] 메모리 보호 설정 실패:", address);
//                     // 실패한 주소를 배열에 저장
//                     failedAddresses.push(address);
//                     return;
//                 }
//                 address.writeByteArray(nopInstructionBytes);
//                 console.log("[*] SVC #0x80이 NOP로 변경되었습니다:", address);
//             } catch (error) {
//                 console.error("[!] 메모리 패치 오류:", error.message);
//             }
//         },
//         onComplete: function () {
//             console.log("[*] 패치가 완료되었습니다.");
//             // 보호 설정 실패한 주소 목록 출력
//             if (failedAddresses.length > 0) {
//                 console.log("[!] 보호 설정에 실패한 주소 목록:");
//                 failedAddresses.forEach(function (failedAddress) {
//                     console.log(" -", failedAddress);
//                 });
//             }
//         }
//     });
// }

// function monitorFailedAddresses() {
//     console.log("[*] 보호 설정에 실패한 주소들의 접근을 감시합니다...");
//     failedAddresses.forEach(function (failedAddress) {
//         Interceptor.attach(failedAddress, {
//             onEnter: function(args) {
//                 console.log("[!] 접근 감지: 보호 설정 실패 주소 호출됨 - 주소:", failedAddress);
//                 console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
//                     .map(DebugSymbol.fromAddress).join("\n"));
//             }
//         });
//     });
// }

// patchSvcToNop();







const sysctlAddress = Module.findExportByName(null, 'sysctl');
console.log("[*] sysctl function address: " + sysctlAddress);

const ptraceAddress = Module.findExportByName(null, 'ptrace');
console.log("[*] ptrace function address: " + ptraceAddress);

const exitAddress = Module.findExportByName(null, 'exit');
console.log("[*] exit function address: " + exitAddress);
// Signal 처리 함수 후킹
// Interceptor.attach(Module.findExportByName(null, "signal"), {
//     onEnter: function(args) {
//         console.log("[*] signal 함수가 호출되었습니다. Signal:", args[0].toInt32());
//     }
// });



// AntiDebug ptrace
Interceptor.attach(ptraceAddress, {
    onEnter: function (args) {
        console.log("[Ptrace] " + args[0] + " " + args[1] + " " + args[2] + " " + args[3]);
        if (args[0].toInt32() == 31) {
            console.log("[D] Bypassed ptrace");
            args[0] = ptr(-1);
        }
    }
});

Interceptor.attach(exitAddress, {
    onEnter: function (args) {
        console.log(`[*] exit 함수가 호출되었습니다.`);
        console.log("\texit 함수 Backtrace:\n\t" + Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n\t'));
    }
});

// AntiDebug getppid
Interceptor.attach(Module.findExportByName(null, 'getppid'), {
    onEnter(args) {
    },
    onLeave(retval) {
        console.log("[D] Bypassed getppid");
        var ret = retval.toInt32();
        console.log(`[★] RETAVL: ${ret}`)
        if (ret !== 1) {
            console.log("[-] Bypassing it...")
            retval.replace(0x1);
        }
    }
});


// AntiDebug sysctl int sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, const void *newp, size_t newlen);
// sysctl 무력화 스크립트
Interceptor.attach(Module.findExportByName(null, "sysctl"), {
    onEnter: function (args) {
        var mib = args[0];
        var mibArray = [];

        // MIB 배열에서 각 요소를 읽어 디버깅 감지용인지 확인
        for (var i = 0; i < 4; i++) { // 일반적으로 첫 4개의 인자가 디버깅 감지용
            mibArray.push(mib.add(i * 4).readInt());
        }

        // console.log("[*] sysctl 호출 감지: MIB = " + mibArray.join(", "));

        // CTL_KERN(1) + KERN_PROC(14) + KERN_PROC_PID(1)
        // 디버깅 감지용 MIB 배열을 무력화
        if (mibArray[0] === 1 && mibArray[1] === 14 && mibArray[2] === 1) {
            // console.log("[*] 디버깅 감지 요청을 무력화합니다.");

            this.bypass = true;  // onLeave에서 확인하기 위한 플래그 설정
        }
    },
    onLeave: function (retval) {
        // 디버깅 감지 요청일 경우, 원하는 값으로 반환값 설정
        if (this.bypass) {
            retval.replace(0); // 0 반환 (디버거 없음)
            console.log("[*] sysctl 디버깅 감지 무력화: 0으로 반환값 변경");
        }
    }
});








const dlopenPtr = Module.getExportByName(null, 'dlopen');
const dlsymPtr = Module.getExportByName(null, 'dlsym');

// Interceptor.attach(dlopenPtr, {
//     onEnter: function(args) {
//         // args[0]에서 문자열을 읽어 null이 아닌 값을 확인
//         const pathPtr = args[0];
//         this.path = pathPtr.isNull() ? "null" : Memory.readUtf8String(pathPtr);
//         console.log("dlopen 호출됨 - 라이브러리:", this.path);
//     },
//     onLeave: function(retval) {
//         console.log("dlopen 완료:", this.path);
//     }
// });



// Interceptor.attach(dlsymPtr, {
//     onEnter: function(args) {
//         this.symbol = args[1].readCString();
//         console.log("dlsym 호출됨 - 심볼:", this.symbol);
//     },
//     onLeave: function(retval) {
//         console.log("dlsym 완료:", this.symbol);
//     }
// });



const nw_protocol_metadata_access_handle = Module.getExportByName(null, "nw_protocol_metadata_access_handle");

Interceptor.attach(nw_protocol_metadata_access_handle, {
    onEnter: function(args) {
        console.log("원래 arg[0] : ", args[0]);
        console.log("원래 arg[4] : ", args[4]);

        // 콜 스택 추적
        console.log("콜 스택 추적:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n"));
    },
    onLeave: function(retval) {
        console.log("    반환값:", retval);
    }
});







// const nw_hash_table_apply = Module.getExportByName(null, "nw_hash_table_apply");

// Interceptor.attach(nw_hash_table_apply, {
//     onEnter: function(args) {
//         // console.log("[*] nw_hash_table_apply 호출됨 - 해시 테이블 순회 시작");

//         // // 인자 값 출력
//         // for (let i = 0; i < 5; i++) {  // 일반적으로 5개 정도의 인자를 확인합니다.
//         //     try {
//         //         console.log("    args[" + i + "]:", args[i]);

//         //         // 인자가 포인터라면, 첫 16바이트를 덤프해서 내용 확인
//         //         const data = Memory.readByteArray(args[i], 16);
//         //         console.log("    args[" + i + "] 내용 (hexdump):", hexdump(data, { offset: 0, length: 16, header: false, ansi: false }));
//         //     } catch (e) {
//         //         console.log("    args[" + i + "]: 메모리 접근 불가 또는 포인터 아님");
//         //     }
//         // }
//     },
//     onLeave: function(retval) {
//         // 원본 반환값 출력
//         console.log("[*] nw_hash_table_apply 원본 반환값:", retval);

//         // 필요에 따라 반환값을 조작할 수 있습니다.
//         // 예: retval.replace(ptr(0)); 로 반환값을 수정할 수 있음

//         // 반환값을 원래대로 유지
//         // retval.replace(ptr(0)); 
//         // console.log("[*] nw_hash_table_apply 반환 완료");
//     }
// });


// // nw_protocol_options_access_handle 후킹
// const symbolName1 = "nw_protocol_options_access_handle";
// const addr1 = Module.findExportByName(null, symbolName1);

// if (addr1) {
//     Interceptor.attach(addr1, {
//         onEnter: function (args) {
//             console.log(`[*] ${symbolName1} 호출됨`);
//             for (let i = 0; i < 5; i++) { // 최대 5개의 인자 출력
//                 console.log(`  args[${i}]: ${args[i]}`);
//             }
//         },
//         onLeave: function (retval) {
//             console.log(`[*] ${symbolName1} 원래 반환값: ${retval}`);
//             retval.replace(0); // 반환값을 항상 0으로 설정
//             console.log(`[*] ${symbolName1} 수정된 반환값: ${retval}`);
//         }
//     });
// } else {
//     console.log(`[!] ${symbolName1}를 찾을 수 없습니다`);
// }



// `nw_protocol_boringssl_copy_definition` 후킹
// const symbolName = "nw_protocol_boringssl_copy_definition";
// const addr = Module.findExportByName(null, symbolName);

// if (addr) {
//     Interceptor.attach(addr, {
//         onLeave: function (retval) {
//             console.log(`[*] ${symbolName} 반환값: ${retval}`);

//             // 반환값의 메모리 내용을 읽기
//             try {
//                 // 메모리에서 64바이트를 읽어 출력
//                 const memoryContent = Memory.readByteArray(retval, 128);
//                 console.log(`[*] ${symbolName} 반환값 메모리 내용 (64 bytes):`, memoryContent);
//             } catch (error) {
//                 console.log(`[!] 메모리 읽기 중 오류 발생: ${error}`);
//             }
//         }
//     });
// } else {
//     console.log(`[!] ${symbolName}를 찾을 수 없습니다`);
// }









// // 데이터 추출 함수
// if (ObjC.available) {
//     console.log("20초 후에 모든 클래스와 메서드를 추출합니다...");

//     // 20초(20000ms) 후에 실행
//     setTimeout(function() {
//         console.log("모든 클래스와 메서드를 추출하여 send로 전송합니다...");

//         var classNames = Object.keys(ObjC.classes);

//         classNames.forEach(function(className) {
//             try {
//                 var cls = ObjC.classes[className];
//                 var methods = cls.$methods;

//                 // 클래스와 메서드 정보를 Python으로 전송
//                 send({ className: className, methods: methods });
//             } catch (e) {
//                 console.error("[!] 클래스 로드 오류: " + className + " - " + e);
//             }
//         });

//         console.log("모든 클래스와 메서드 추출이 완료되었습니다.");
//     }, 20000); // 20000 밀리초 = 20초

// } else {
//     console.log("Objective-C가 사용 불가능합니다. 이 스크립트는 iOS에서만 동작합니다.");
// }







// // nw_protocol_boringssl_copy_definition 후킹
// const nw_protocol_boringssl_copy_definition = Module.getExportByName(null, "nw_protocol_boringssl_copy_definition");
// Interceptor.attach(nw_protocol_boringssl_copy_definition, {
//     onEnter: function(args) {
//         console.log("[*] nw_protocol_boringssl_copy_definition 호출됨");
//     },
//     onLeave: function(retval) {
//         console.log("[*] nw_protocol_boringssl_copy_definition 완료");
//     }
// });








// if (SecTrustSetPolicies) {
//     Interceptor.attach(SecTrustSetPolicies, {
//         onEnter: function (args) {
//             console.log("[*] SecTrustSetPolicies 호출됨");

//             // 첫 번째 인자는 SecTrust 객체
//             const secTrust = args[0];
//             console.log("  - SecTrust 객체:", secTrust);

//             // 두 번째 인자는 정책 (SecPolicyRef)
//             const policy = args[1];
//             console.log("  - 정책 객체 (SecPolicyRef):", policy);

//             // 정책의 구체적인 내용을 확인하고 싶다면, 이를 ObjC 객체로 변환하여 상세 정보 출력
//             try {
//                 const policyObj = new ObjC.Object(policy);
//                 console.log("  - 정책 객체 상세 정보:", policyObj.toString());
//             } catch (error) {
//                 console.log("[!] 정책 객체 상세 정보를 출력할 수 없음:", error.message);
//             }
//         },
//         onLeave: function (retval) {
//             console.log("[*] SecTrustSetPolicies 종료");
//         }
//     });
// }




// if (ObjC.available) {
//     console.log("[*] 15초 후 모든 메서드 덤프 시작");

//     setTimeout(function() {
//         console.log("[*] 메서드 덤프 중...");

//         // 모든 클래스 순회
//         for (const className in ObjC.classes) {
//             // Alamofire와 관련된 클래스만 출력
//             if (className.startsWith("Alamofire")) {
//                 console.log(`\n[*] 클래스 발견: ${className}`);

//                 const methods = ObjC.classes[className].$ownMethods;
//                 for (let i = 0; i < methods.length; i++) {
//                     console.log(` - 메서드: ${methods[i]}`);
//                 }
//             }
//         }

//         console.log("[*] 메서드 덤프 완료");
//     }, 15000);  // 15초 지연 후 실행

// } else {
//     console.log("[!] ObjC 환경이 아님 - 스크립트 종료");
// }



// const gettimeofdayPtr = Module.getExportByName(null, 'gettimeofday');
// Interceptor.attach(gettimeofdayPtr, {
//     onEnter: function(args) {
//         this.startTime = new Date().getTime();  // 함수 호출 시작 시간 기록
//     },
//     onLeave: function(retval) {
//         const newTime = new Date().getTime();
//         const timeDiff = newTime - this.startTime;

//         // 반환값을 수정하지 않고 함수의 실제 결과에 기초하여 차이 값을 콘솔에 표시
//         console.log("gettimeofday 호출 완료 - 시간 차이:", timeDiff < 10 ? timeDiff : 10);
//     }
// });


// // mach_absolute_time 후킹: 항상 일정 시간만큼 증가하도록 조작
// const mach_absolute_timePtr = Module.getExportByName(null, 'mach_absolute_time');
// Interceptor.attach(mach_absolute_timePtr, {
//     onLeave: function(retval) {
//         const fixedTime = 100000;  // 일정한 시간 값 반환
//         retval.replace(ptr(fixedTime));
//         console.log("mach_absolute_time 호출 수정 - 고정 시간:", fixedTime);
//     }
// });

// // fork 후킹: 디버거 감지를 무력화하기 위해 fork의 반환값을 조작
// const forkPtr = Module.getExportByName(null, 'fork');
// Interceptor.attach(forkPtr, {
//     onLeave: function(retval) {
//         retval.replace(0);  // 자식 프로세스처럼 반환
//         console.log("fork 호출 수정 - 자식 프로세스로 변경");
//     }
// });

// // execve 후킹: 특정 프로세스를 실행할 때 실행을 차단하거나 조작
// const execvePtr = Module.getExportByName(null, 'execve');
// Interceptor.attach(execvePtr, {
//     onEnter: function(args) {
//         const command = args[0].readCString();
//         console.log("execve 호출됨 - 명령어:", command);

//         // 특정 명령어 실행 차단
//         if (command.includes("target_process")) {
//             console.log("execve 호출 차단 - 명령어:", command);
//             retval.replace(-1);  // 실패한 것처럼 반환
//         }
//     }
// });



// // Hooking readlink file check
// var readlinkPtr = Module.findExportByName(null, 'readlink');
// if (readlinkPtr !== null) {
//     Interceptor.attach(readlinkPtr, {
//         onEnter: function (args) {
//             var path = Memory.readUtf8String(args[0]);
//             console.log("[*] \x1b[36mreadlink\x1b[0m called with path: \x1b[33m" + path + "\x1b[0m");
//         },
//         onLeave: function (retval) {
//             retval.replace(ptr('0xffffffffffffffff'));
//             console.log("[*] \x1b[36mreadlink\x1b[0m bypassed with value: \x1b[32m" + retval + "\x1b[0m");
//         }
//     });
// } else {
//     console.log("[-] \x1b[31mreadlink\x1b[0m not found");
// }



// Interceptor.attach(Module.findExportByName(null, 'syscall'), {
//     onEnter: function (args) {
//         if (args[0].toInt32() == 26 && args[1].toInt32() == 31) {
//             console.log("[D] Bypassed ptrace+syscall");
//             args[1] = ptr(0x0);
//         }
//     }
// });

// //AntiDebug isatty
// Interceptor.attach(Module.findExportByName(null, 'isatty'), {
//     onEnter(args) {
//     },
//     onLeave(retval) {
//         console.log("[D] Bypassed isatty");
//         return 0;
//     }
// });

// // AntiDebug ioctl
// Interceptor.attach(Module.findExportByName(null, 'ioctl'), {
//     onEnter(args) {
//     },
//     onLeave(retval) {
//         console.log("[D] Bypassed ioctl");
//         return -1;
//     }
// });

