.. SPDX-License-Identifier: GPL-2.0
.. Copyright (C) 2022 Casey Schaufler <casey@schaufler-ca.com>
.. Copyright (C) 2022 Intel Corporation

=====================================
Linux Security Modules
=====================================

:Author: Casey Schaufler
:Date: July 2023

Linux security modules (LSM) provide a mechanism to implement
additional access controls to the Linux security policies.

The various security modules may support any of these attributes:

``LSM_ATTR_CURRENT`` is the current, active security context of the
process.
The proc filesystem provides this value in ``/proc/self/attr/current``.
This is supported by the SELinux, Smack and AppArmor security modules.
Smack also provides this value in ``/proc/self/attr/smack/current``.
AppArmor also provides this value in ``/proc/self/attr/apparmor/current``.

``LSM_ATTR_EXEC`` is the security context of the process at the time the
current image was executed.
The proc filesystem provides this value in ``/proc/self/attr/exec``.
This is supported by the SELinux and AppArmor security modules.
AppArmor also provides this value in ``/proc/self/attr/apparmor/exec``.

``LSM_ATTR_FSCREATE`` is the security context of the process used when
creating file system objects.
The proc filesystem provides this value in ``/proc/self/attr/fscreate``.
This is supported by the SELinux security module.

``LSM_ATTR_KEYCREATE`` is the security context of the process used when
creating key objects.
The proc filesystem provides this value in ``/proc/self/attr/keycreate``.
This is supported by the SELinux security module.

``LSM_ATTR_PREV`` is the security context of the process at the time the
current security context was set.
The proc filesystem provides this value in ``/proc/self/attr/prev``.
This is supported by the SELinux and AppArmor security modules.
AppArmor also provides this value in ``/proc/self/attr/apparmor/prev``.

``LSM_ATTR_SOCKCREATE`` is the security context of the process used when
creating socket objects.
The proc filesystem provides this value in ``/proc/self/attr/sockcreate``.
This is supported by the SELinux security module.

``LSM_ATTR_UNSHARE`` is used to unshare the LSM-specific namespace for
the process.
When passed to ``lsm_set_self_attr(2)``, the LSM-specific namespace
for the specified LSM id is immediately unshared in a similar manner
to the ``unshare(2)`` system call for other Linux namespaces. When
passed to ``lsm_get_self_attr(2)``, ``ctx->ctx_len`` is set to ``1``
and ``ctx->ctx[0]`` is set to a boolean (``0`` or ``1``) that
indicates whether the LSM-specific namespace for the specified LSM id
has been unshared and not yet fully initialized (e.g. no policy yet
loaded).

Kernel interface
================

Set a security attribute of the current process
-----------------------------------------------

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_set_self_attr

Get the specified security attributes of the current process
------------------------------------------------------------

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_get_self_attr

.. kernel-doc:: security/lsm_syscalls.c
    :identifiers: sys_lsm_list_modules

Additional documentation
========================

* Documentation/security/lsm.rst
* Documentation/security/lsm-development.rst
