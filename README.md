# [zhpe-support](https://github.com/HewlettPackard/zhpe-support.git)
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

## Building just the driver and helper into ${TEST_DIR}

### 1. Clone libfabric-stuff into ${SRC_DIR}
	$ cd ${SRC_DIR}
    $ git clone https://github.com/HewlettPackard/zhpe-support.git

### 2. Generate makefiles and build/install driver
    $ cd ${SRC_DIR}/libfabric-stuff
    $ ./prep.sh ${TEST_DIR}
	$ make driver

## Building libfabric-stuff, libfabric-zhpe, and OpenMPI (with libfabric support). Everything will be installed into ${TEST_DIR}

### 1. Clone source trees in ${SRC_DIR}
	$ cd ${SRC_DIR}
    $ git clone https://github.com/HewlettPackard/zhpe-support.git
	$ git clone -b zhpe https://github.com/HewlettPackard/zhpe-libfabric.git
	$ git clone https://github.com/open-mpi/ompi.git
	$ cd libfabric-zhpe
	$ cd ../ompi
	$ git checkout v3.0.0

### 2. Build and install zhpe library
    $ cd ${SRC_DIR}/libfabric-stuff
    $ ./prep.sh -f ${TEST_DIR} ${TEST_DIR}
	$ make libzhpeq

### 3. Build and install libfabric-zhpe with zhpe support
	$ cd ${SRC_DIR}/libfabric-zhpe
	$ ./autogen.sh
    $ ./configure --prefix=${TEST_DIR} --enable-zhpe=${TEST_DIR}
    ... clipped ...
    ***
    *** Built-in providers:	zhpe shm rxd rxm tcp udp verbs sockets 
    *** DSO providers:	
    ***
	$ make -j install

### 4. Build the rest of the zhpe code that requires libfabric (except MPI tests)
    $ cd ${SRC_DIR}/libfabric-stuff
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
    $ cd ${SRC_DIR}/libfabric-stuff
	$ ./prep_mpi.sh -m ${TEST_DIR} ${TEST_DIR}
	$ make mpi_tests

## Test low level APIs:  xingpong
### Invoke it without arguments for usage:
    $ export LD_LIBRARY_PATH=${TEST_DIR}/lib
    $ ${TEST_DIR}/libexec/xingpong

### Here is how to run xingpong on one or two nodes (the server is hostname1), using the sockets provider.
(If another provider (e.g., verbs) is available on your system you may specify it using the -p option.)

#### 1. Start the server on the hostname1 
(In this example, we're starting the server as a background process so that we can run the client in the foreground):
    $ ${TEST_DIR}/libexec/xingpong 2222  &
    
#### 2. Start a client and point it at the server (hostname1 in the example below):
    $ ${TEST_DIR}/libexec/xingpong -o -p sockets 2222 hostname1 1 1 1

## Test libfabric RDMA APIs:  ringpong
ringpong is very similar to xingpong, except that it uses the libfabric APIs
instead of the libzhpeq APIs to do the data transfers. Replace the command
in above example with "ringpong" and use "-p zhpe" to exercise the libfabric
zhpe provider.

## Running OpenMPI over libfabric-zhpe (Using the right options.)
OpenMPI will try multiple providers automatically and getting it to
run a specific provider under the correct circumstances is problematic.
We want to use the libfabric-zhpe for all cross-node communication, but
not for same node communication. The verbose options below can allow you
to verify the correct transports are being used, but are not required
for correct operation.

    $ export LD_LIBRARY_PATH=${TEST_DIR}/lib
	$ ${TEST_DIR}/bin/mpirun -x LD_LIBRARY_PATH --hostfile ~/hostfile -n 2 --bind-to socket --mca btl ^openib --mca mtl_ofi_provider_include zhpe --mca btl_base_verbose 100 --mca mtl_base_verbose 100 --mca pml_base_verbose 100 <command>

