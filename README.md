Support for the Libfabric [zhpe](https://github.com/HewlettPackard/zhpe-libfabric/tree/zhpe) Provider
-----------------------------------------------------
# What is libzhpeq ?
The libzhpeq library exposes an API for software to submit and track
requests to the Gen-Z Bridge transmit and receive data movers (XDM and
RDM blocks).

Ultimately, the libzhpeq library will enable software running on a
processor to use bridge hardware to perform data transfers and other
operations over a Gen-Z fabric.  Immediately, developers can use the
libzhpeq library to write software that performs data transfers and
other operations over existing hardware (e.g., InfiniBand Verbs, ROCE, or
sockets).  While performance on existing hardware obviously differs from
the actual PathForward hardware, we can use the the APIs and programming
model exposed by the libzhpeq library now to develop software now.

For example, we are using the libzhpeq library to implement a Gen-Z
provider for the Libfabric API, which will enable existing applications
that run on high performance computing middleware such as MPI, OpenSHMEM,
or GASNet to take advantage of Gen-Z.

# When should I use it?
If you are writing systems software and want to use the data movers as
directly as you can, but don't want to write your own device driver to
communicate directly with the Bridge hardware, then the libzhpeq library
is currently your best option.  If you are writing application software,
then we suggest using MPI or some other middleware supported by Libfabric.
We do request that you let us know what your application does, as that
will inform our evaluation of our Gen-Z provider for Libfabric.

# What does it NOT do?
Although eventually this will be supported, currently the libzhpeq library
does not enable a process to mmap and directly write to a remote memory
region without using a data mover.

# How do I use it?
A process can use the libzhpeq library to allocate a zhpe queue (zhpeQ).
The process can use that zhpeq to register a memory region (thereby
mapping it to a window in the data mover's address space) and to get
a key for that registered memory region that it can give to a process
running on a remote node so that the remote process can register that
memory region with its own zhpeq and map it to a window in its own data
mover's address space.

Once a remote memory region has been mapped to a local data mover's
address space, the process can create and submit requests to the zhpeq
for its local data mover to move data between local DRAM and the remote
node's DRAM.

For an example of this process, please see xingpong (below) and also hello_libzhpeq .

# How to install and build?

Note that you need at least one Linux machine and an environment that
can support Libfabric.  The machine does not need to have InfiniBand;
you can use the sockets provider. To build support for Infiniband,
you must have the libibverbs-dev and librdmacm-dev packages installed.
In general, it might be best to insure that the build-dependencies for
the distro OpenMPI release are installed before trying to build.

## Notes about the build dependencies and test environment

The code has been built and tested on Ubuntu Xenial. The build dependencies for Libfabric and Open MPI must be installed. Additionally, there is a issue with building Open MPI v3.0.0 from source with support for Libfabric with the patched version of libtool installed.

The emulation provided by the libzhpeq library has been mostly tested using the Libfabric verbs provider over Infiniband/RoCE hardware, but this hardware is not required. In the absence of such hardware, the library should use the sockets provider. You can build the Libfabric software with support for InfiniBand verbs without hardware, you just need to install the proper libraries. These can either be the development libraries from the Ubuntu repository or [Mellanox OFED](http://www.mellanox.com/page/products_dyn?product_family=26).

### 1. Install dependencies
	$ sudo -i apt-get install build-essential linux-headers-$(uname -r) cmake valgrind libudev-dev git wget flex
	$ sudo -i apt-get build-dep openmpi libtool
	$ sudo -i apt-get install librdmacm-dev # optional: not needed if OFED installed or verbs not required
    
### 2. Install libtool from source
	$ wget http://ftpmirror.gnu.org/libtool/libtool-2.4.6.tar.gz
	$ tar -xzf libtool-2.4.6.tar.gz
	$ cd libtool-2.4.6
	$ ./configure
	$ make	
	$ sudo make install
Make sure the new version of libtoolize is first in your PATH.
   
## Building zhpe-support, zhpe-libfabric, and OpenMPI (with libfabric support). Everything will be installed into ${TEST_DIR}

### 1. Clone source trees in ${SRC_DIR}
	$ cd ${SRC_DIR}
	$ git clone https://github.com/HewlettPackard/zhpe-driver.git
	$ git clone https://github.com/HewlettPackard/zhpe-support.git
	$ git clone -b zhpe https://github.com/HewlettPackard/zhpe-libfabric.git
	$ git clone https://github.com/open-mpi/ompi.git
	$ (cd ompi; git checkout v4.0.0rc1)
(Open MPI version 3.1.1 has also been tested, but we are focused on v4.0.0rc1 at this point because for atomic support we depend upon the btl/ofi module that is present in rc1 but was dropped from the v4.0.0x release due to some issues involving the OminPath provider. The btl/ofi module will be brought back in a later release.)

### 2. Build and install zhpe library
	$ cd ${SRC_DIR}/zhpe-support
	$ ./prep.sh -f ${TEST_DIR} ${TEST_DIR}
	$ make libzhpeq

### 3. Build and install zhpe provider with zhpe support
	$ cd ${SRC_DIR}/zhpe-libfabric
	$ ./autogen.sh
	$ LD_LIBRARY_PATH=${TEST_DIR}/lib ./configure --prefix=${TEST_DIR} --enable-zhpe=${TEST_DIR}
	... clipped ...
	***
	*** Built-in providers:	zhpe shm rxd rxm tcp udp verbs sockets 
	*** DSO providers:	
	***
	$ make -j install

### 4. Build the rest of the zhpe code that requires libfabric (except MPI tests)
	$ cd ${SRC_DIR}/zhpe-support
	$ make

### 5. Build and install OpenMPI with libfabric support
	$ cd ${SRC_DIR}/ompi
	$ ./autogen.pl
	$ LD_LIBRARY_PATH=${TEST_DIR}/lib ./configure --prefix=${TEST_DIR} --without-ucx --with-libfabric=${TEST_DIR}
	... clipped ...
	Transports
	-----------------------
	Cray uGNI (Gemini/Aries): no
	Intel Omnipath (PSM2): no
	Intel SCIF: no
	Intel TrueScale (PSM): no
	Mellanox MXM: no
	Open UCX: no
	OpenFabrics Libfabric: yes
	OpenFabrics Verbs: yes
	Portals4: no
	Shared memory/copy in+copy out: yes
	Shared memory/Linux CMA: yes
	Shared memory/Linux KNEM: no
	Shared memory/XPMEM: no
	TCP: yes
	... clipped ...
	$ make -j install

### 6. Build and install MPI tests
	$ cd ${SRC_DIR}/zhpe-support
	$ ./prep_mpi.sh -m ${TEST_DIR} ${TEST_DIR}
	$ make mpi_tests

## Test low level APIs:  xingpong
### Invoke it without arguments for usage:
	$ export LD_LIBRARY_PATH=${TEST_DIR}/lib
	$ ${TEST_DIR}/libexec/xingpong

### Here is how to run xingpong on one or two nodes (the server is hostname1), using the first provider found.
The sockets provider is tried last and will be used if no others can be found. If you wish to force a specific provider
that supports RDM endpoints (e.g., verbs), you may specify this by exporting  
ZHPE_BACKEND_LIBFABRIC_PROV=**provider** for both the client and server. A specific domain may be
specified by exporting ZHPE_BACKEND_LIBFABRIC_PROV=**domain** , in which case the hostname or IP address specified for by the client to point at the server must support the specified domain.


#### 1. Start the server on the hostname1 (running the server in the background)
	$ ${TEST_DIR}/libexec/xingpong 2222  &
    
#### 2. Start a client and point it at the server (hostname1 in the example below):
	$ ${TEST_DIR}/libexec/xingpong -o 2222 hostname1 1 1 1


## Test libfabric RDMA APIs:  ringpong
ringpong is very similar to xingpong, except that it uses the libfabric APIs
instead of the libzhpeq APIs to do the data transfers. Replace the command
in above example with "ringpong" and for the client use "-r -p zhpe" to exercise the libfabric
zhpe provider.

## Running OpenMPI over zhpe-libfabric (Using the right options.)
OpenMPI will try multiple providers automatically and getting it to
run a specific provider under the correct circumstances is problematic.
We want to use the libfabric-zhpe for all cross-node communication, but
not for same node communication. The verbose options below can allow you
to verify the correct transports are being used, but are not required
for correct operation.

	$ export LD_LIBRARY_PATH=${TEST_DIR}/lib
	$ ${TEST_DIR}/bin/mpirun -x LD_LIBRARY_PATH --hostfile ~/hostfile -n 2 --bind-to socket --mca btl ^openib,tcp,vader --mca mtl_ofi_provider_include zhpe -x ZHPE_BACKEND_LIBFABRIC_PROV=provider --mca btl_base_verbose 100 --mca mtl_base_verbose 100 --mca pml_base_verbose 100 <command>

