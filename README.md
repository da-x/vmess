## `vmess` - experimental VM manager for libvirt

Highlights:

* VM image files being the first class citizen instead of defined domains. Actual VMs can be defined from ready XML templates.
* VM image files are a hierarchy of external-only VM snapshots, where only the leafs are runnable VMs.
* VM image files can be either persistent or exist on `/tmp` and be entirely volatile.
* VM image filename translates to libvirt domain name, auto-updated ssh config to access the running VM via its given domain name.
* VM image storage pool can be in your home dir rather than then `/var/lib` (requires `sudo` config).
* Clearly present memory usage of running VMs and disk sizes of their images.


### Configuration and command line

**TBD**. I'll post documentation once the interfaces stabilize.


### Installation

Install Rust toolchain, and do `cargo install --path .`
