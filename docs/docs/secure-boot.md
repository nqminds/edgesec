# ManySecured Secure Boot

## State of the art

### ARM Trusted Firmware

[ARM Trusted Firmware-A](https://trustedfirmware-a.readthedocs.io/en/latest/) (TF-A) provides a reference implementation of secure world software for [Armv7-A and Armv8-A](https://developer.arm.com/products/architecture/a-profile), including a [Secure Monitor](http://www.arm.com/products/processors/technologies/trustzone/tee-smc.php) executing at Exception Level 3 (EL3). It implements various Arm interface standards, such as:

- The [Power State Coordination Interface (PSCI)](http://infocenter.arm.com/help/topic/com.arm.doc.den0022d/Power_State_Coordination_Interface_PDD_v1_1_DEN0022D.pdf)
- [Trusted Board Boot Requirements CLIENT (TBBR-CLIENT)](https://developer.arm.com/docs/den0006/latest/trusted-board-boot-requirements-client-tbbr-client-armv8-a)
- [SMC Calling Convention](https://developer.arm.com/docs/den0028/latest)
- [System Control and Management Interface (SCMI)](http://infocenter.arm.com/help/topic/com.arm.doc.den0056a/DEN0056A_System_Control_and_Management_Interface.pdf)
- [Software Delegated Exception Interface (SDEI)](http://infocenter.arm.com/help/topic/com.arm.doc.den0054a/ARM_DEN0054A_Software_Delegated_Exception_Interface.pdf)

![ARM TEE](images/arm-tee.jpg)

Theoretically this specification allows for remote attestation provided that the ARM Trusted Firmware implementation sufficiently implements TrustZone. Unfortunately, given that it’s up to every individual manufacturer, this has to be evaluated on a case-by-case basis.

### High Assurance Boot

High Assurance Boot (HAB) is an optional feature in the i.MX SOC family from NXP, which allows you to make sure only software images signed by you can be executed on the SOC.
It incorporates boot ROM level security which cannot be altered after programming the appropriate one-time electrically programmable fuses (eFuses). The boot ROM is responsible for loading the initial software image from the boot medium (usually this initial software is a bootloader such as SPL/U-Boot. HAB enables the boot ROM to authenticate the initial software image by using digital signatures. It also provides a mechanism to establish a chain of trust for the remaining software components (such as the kernel image) and thus to establish a secure state of the system.

HAB authentication is based on public key cryptography using the RSA algorithm.
It consists of the following stages:

1. Offline signing of the software images using private keys.
   The image data is signed offline using a series of private keys. This is done using NXP's Code Signing Tool, and Variscite's scripts, which make the process extremely easy and simple.

2. Fusing the i.MX SOC with the corresponding public keys.
   The key structure is called a PKI tree and Super Root Keys (SRK) are components of it. A table of the public SRKs are hashed and permanently written to the SOC using eFuses.
   You have the option to let the processor keep running unsigned images, while creating useful HAB messages, until you decide to “close” it by writing a dedicated bit using another eFuse. This allows you to test the sign-authenticate process and verify that it was done correctly before completely and permanently “closing” the processor to only execute your signed images.

3. Authentication of the software images on the target during boot time.
   The signed image data is verified on the i.MX processor using the corresponding public keys.
   HAB evaluates the SRK table included in the signature by hashing it and comparing the result to the SRK fuse values. If the SRK verification is successful, this establishes the root of trust, and the remainder of the signature can be processed to authenticate the image.

Once the initial bootloader is authenticated and executed, the chain of trust continues by authenticating each of the next loaded images before executing them.
E.g. The boot ROM authenticates SPL, SPL authenticates U-Boot, and U-Boot authenticates the Linux kernel.

![HAB operation](images/HAB_operation.png)

Advantages of NXP's HAB is that the keys are write-protected behind one-time programmable (OTP) fuses and one can permanently fuse the keys to the board. Disadvantages is the proprietary toolchain for signing binaries.

### NVIDIA Jetson Nano boot security

NVIDIA® Jetson™ provides boot security using the Secureboot package. Secureboot prevents execution of unauthorized boot codes through chain of trust. The root-of-trust is on-die bootROM code that authenticates boot codes such as BCT, Bootloader, and warmboot vector using Public Key Cryptography (PKC) keys stored in write-once-read-multiple fuse devices. You can also use Secureboot Key (SBK) to encrypt Bootloader images.

NVIDIA SoCs contain multiple fuses that control different items for security and boot. Once a fuse bit is set to 1, you cannot change its value back to 0. For example, a fuse value of 1 (0x01) can be changed to 3 (0x03) or 5 (0x05), but not to 4 (0x4) because bit 0 is already programmed to 1.

Advantages and disadvantage are similar to HAB from NXP.

### Verified U-Boot

[U-Boot](http://www.denx.de/wiki/U-Boot) 2013.07 introduces a feature allowing for the verification of a kernel and other images. This can be used to implement a form of secure boot which we will call "verified boot", to avoid confusion with the UEFI implementation. U-Boot's new verified boot feature provides a mechanism for verifying images while still allowing them to be field-upgraded. It fits in seamlessly with the existing image loading infrastructure in U-Boot.

U-Boot verified boot relies on two familiar technologies: [cryptographic hashing](http://en.wikipedia.org/wiki/Hash_function) (e.g. [SHA-1](http://en.wikipedia.org/wiki/SHA-1)) and [public key cryptography](http://en.wikipedia.org/wiki/Public-key_cryptography) (e.g. [RSA](<http://en.wikipedia.org/wiki/RSA_(algorithm)>)). Using these technologies it is possible to distribute images and have them verified on a device. Specifically we can create a key, hash an image, sign that hash, and publish the public key. On the device we can obtain an image and verify it was signed by the private key.

Images can be chained one after the other and signed in reverse order either using the same keys or sub-keys (keys derived from other keys). For example, U-Boot may load an image containing a new U-Boot, then boot that. That U-Boot in turn may load an image containing a kernel. Doing that would allow U-Boot itself to be updated with the firmware without risking having an unbootable device due to a bad update.

In principle this chain can be any length, but there must be an initial trusted image ("root of trust") that can start the process. This can be stored in read-only media during manufacture or perhaps protected by on-chip crypto using its own signing scheme. The "root of trust" U-Boot must include the initial public key, held in U-Boot's [device tree](http://git.denx.de/?p=u-boot.git;a=blob;f=doc/README.fdt-control;) (often called the flattened device tree or FDT). A more sophisticated scheme would allow the public keys to be provided by the user, perhaps by inserting an SD card containing the key. This could be implemented using a U-Boot script or with a more sophisticated user interface.

A [Trusted Platform Module](http://en.wikipedia.org/wiki/Trusted_Platform_Module) (TPM) can be used to hold rollback counters, to protect against rolling back to an older, compromised firmware. U-Boot also provides TPM support for trusted boot and remote attestation.

### UEFI Secure Boot

UEFI Secure boot is a verification mechanism for ensuring that code launched by firmware is trusted.

Proper, secure use of UEFI Secure Boot requires that each binary loaded at boot is validated against known keys, located in firmware, that denote trusted vendors and sources for the binaries, or trusted specific binaries that can be identified via cryptographic hashing.

Most x86 hardware comes from the factory pre-loaded with Microsoft keys. This means we can generally rely on the firmware on these systems to trust binaries that are signed by Microsoft, and the Linux community heavily relies on this assumption for Secure Boot to work. This is the same process used by Red Hat and SUSE, for instance.

Many ARM and other architectures also support UEFI Secure Boot, but may not be pre-loading keys in firmware. On these architectures, it may be necessary to re-sign boot images with a certificate that is loaded in firmware by the owner of the hardware.

One major thing to keep in mind: UEFI secure boot requires a TPM to verify the bootloader.
