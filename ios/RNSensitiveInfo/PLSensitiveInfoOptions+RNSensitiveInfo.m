//
//  PLSensitiveInfoOptions+RNSensitiveInfo.m
//  react-native-sensitive-info
//
//  Created by Mai Anh Vu (Padlet) on 2/7/20.
//

#import "PLSensitiveInfoOptions+RNSensitiveInfo.h"
#import <React/RCTConvert.h>
#import <Security/Security.h>

@implementation PLSensitiveInfoOptions (RNSensitiveInfo)

#define RCT_EXTRACT_VALUE_IF_NONNULL(property, conversion, key) {\
id value = [RCTConvert conversion : dictionary[ key ]];\
if (value) { self. property = value; }\
}

- (instancetype)initWithDictionary:(NSDictionary<NSString *,id> *)dictionary {
    if (self = [self init]) {
        RCT_EXTRACT_VALUE_IF_NONNULL(keychainService, NSString, @"keychainService");
        RCT_EXTRACT_VALUE_IF_NONNULL(operationPrompt, NSString, @"kSecUseOperationPrompt");
        RCT_EXTRACT_VALUE_IF_NONNULL(localizedFallbackTitle, NSString, @"kLocalizedFallbackTitle");
        
        if (dictionary[@"touchID"]) {
            self.useTouchID = [RCTConvert BOOL:dictionary[@"touchID"]];
        }
        
        NSString *kSecAccessControl = [RCTConvert NSString:dictionary[@"kSecAccessControl"]];
        if (kSecAccessControl) {
            self.accessControl = [self convertkSecAccessControl:kSecAccessControl];
        }
        
        NSString *kSecAttrAccessible = [RCTConvert NSString:dictionary[@"kSecAttrAccessible"]];
        if (kSecAttrAccessible) {
            self.accessible = [self convertkSecAttrAccessible:kSecAttrAccessible];
        }
        
        if (dictionary[@"kSecAttrSynchronizable"]) {
            if ([[RCTConvert NSString:dictionary[@"kSecAttrSynchronizable"]] isEqualToString:@"kSecAttrSynchronizableAny"]) {
                self.synchronizable = PLSensitiveInfoSynchronizableAny;
            } else if ([RCTConvert BOOL:dictionary[@"kSecAttrSynchronizable"]]) {
                self.synchronizable = PLSensitiveInfoSynchronizableYes;
            } else {
                self.synchronizable = PLSensitiveInfoSynchronizableNo;
            }
        }
    }
    return self;
}

- (CFStringRef)convertkSecAttrAccessible:(NSString *)key {
    if([key isEqual: @"kSecAttrAccessibleAfterFirstUnlock"]){
        return kSecAttrAccessibleAfterFirstUnlock;
    }
    if([key isEqual: @"kSecAttrAccessibleAlways"]){
        return kSecAttrAccessibleAlways;
    }
    if([key isEqual: @"kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly"]){
        return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly;
    }
    if([key isEqual: @"kSecAttrAccessibleWhenUnlockedThisDeviceOnly"]){
        return kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
    }
    if([key isEqual: @"kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"]){
        return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
    }
    if([key isEqual: @"kSecAttrAccessibleAlwaysThisDeviceOnly"]){
        return kSecAttrAccessibleAlwaysThisDeviceOnly;
    }
    return kSecAttrAccessibleWhenUnlocked;
}

- (SecAccessControlCreateFlags)convertkSecAccessControl:(NSString *)key {
    if (@available(iOS 9.0, *)) {
        if([key isEqual: @"kSecAccessControlApplicationPassword"]){
            return kSecAccessControlApplicationPassword;
        }
        if([key isEqual: @"kSecAccessControlPrivateKeyUsage"]){
            return kSecAccessControlPrivateKeyUsage;
        }
        if([key isEqual: @"kSecAccessControlDevicePasscode"]){
            return kSecAccessControlDevicePasscode;
        }
        if([key isEqual: @"kSecAccessControlTouchIDAny"]){
            return kSecAccessControlTouchIDAny;
        }
        if([key isEqual: @"kSecAccessControlTouchIDCurrentSet"]){
            return kSecAccessControlTouchIDCurrentSet;
        }
    }
    if (@available(iOS 13.0, *)) {
        if ([key isEqual: @"kSecAccessControlBiometryAny"]) {
            return kSecAccessControlBiometryAny;
        }
        if ([key isEqual: @"kSecAccessControlBiometryCurrentSet"]) {
            return kSecAccessControlBiometryCurrentSet;
        }
    }
    return kSecAccessControlUserPresence;
}

@end
