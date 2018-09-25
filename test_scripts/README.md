Scripts to run tests against the Libfabric [zhpe] (https://github.com/HewlettPackard/zhpe-libfabric/tree/zhpe) Provider
-----------------------------------------------------

# Directories
   * ${SRC\_DIR}: ${TEST\_DIR}/src
   * ${SCRIPT\_PARENT\_DIR}: ${SRC\_DIR}/zhpe-support/test_scripts (directory where this README.md file is located) 
   * ${SCRIPT\_DIR}: ${SCRIPT\_PARENT\_DIR}/scripts


These scripts are intended to run tests in a 
self-contained test directory, ${TEST\_DIR}, and
expect a fixed directory structure rooted at ${TEST\_DIR}:

    +--${TEST_DIR}
        +--bin
        +--etc
        +--include
        +--openmpi
        +--rdma
    +--lib
        +--openmpi
        +--pkgconfig
        +--pmix
    +--libexec
        +--osu-micro-benchmarks
    +--share
        +--fabtests
        +--man
        +--openmpi
        +--pmix
    +--src
        +--ompi
        +--zhpe-driver
        +--zhpe-libfabric
        +--zhpe-support
            +--test_scripts
                +--scripts
    +--tests
        +--fabtests
        +--osu-micro-benchmarks-5.4.3
        +--SNAP


# Prepare the Test Directory

## 1. Install zhpe-support, zhpe-libfabric, and OpenMPI (with libfabric support) in ${TEST\_DIR}/src
   * Follow the instructions at https://github.com/HewlettPackard/zhpe-support 

   * Install the following versions:
       * zhpe-support:
       * zhpe-libfabric: 
       * ompi: v4.0.x

## 2. Install SNAP into ${TEST\_DIR}/tests/SNAP
   * URL: https://github.com/lanl/SNAP
   * Follow the instructions given in the SNAP README.md file
   * Hint: make FORTRAN=${TEST\_DIR}/bin/mpif90
 
## 3. Install osu-microbenchmarks-5.4.3 into ${TEST\_DIR}/tests/osu-microbenchmarks-5.4.3
   * Download and unpack: http://mvapich.cse.ohio-state.edu/download/mvapich/osu-micro-benchmarks-5.4.3.tar.gz
   * Follow the instructions given in the README file
   * Hint: LD\_LIBRARY\_PATH=${TEST\_DIR}/lib ./configure CC=${TEST\_DIR}/bin/mpicc CXX=${TEST\_DIR}/bin/mpicxx --prefix=${TEST\_DIR} 

## 4. Install fabtests into ${TEST\_DIR}/tests/fabtests
   * git clone https://github.com/ofiwg/fabtests
   * cd fabtests
   * git checkout v1.6.1 
   * Follow the instructions in the README.md file
   * Hint: LD_LIBRARY_PATH=${TEST\_DIR}/lib ./configure --prefix=${TEST\_DIR} --with-libfabric=${TEST\_DIR}

## 5. (Optional) Install the ibm test suite from the non-public Open MPI test repo ompi-tests into ${TEST\_DIR}/tests/ibm
   * This is optional because this test suite is non-public.
   * Follow the insctructions in the README.md file
   * Hint: LD_LIBRARY_PATH=${TEST\_DIR}/lib ./configure --prefix=${TEST\_DIR} 

   
# Run our general prep and test script
   * Create ~/hostfile . This file should include at least four hosts (IP addresses or hostnames) that support the desired backend transport that the zhpe Libfabric provider should use, which it will do using that transport's provider for libfabric.
   * ${SCRIPT\_DIR}/prep\_and\_test\_testdir.sh -p ${TEST\_DIR} -z ${ZHPE_BACKEND_LIBFABRIC_PROV}
     where ${ZHPE_BACKEND_LIBFABRIC_PROV} is the backend libfabric provider that the zhpe provider for libfabric should use. (E.g., verbs). Note that we have tested only with the verbs provider. If, however, you do not have machines that support verbs, then you can try the sockets provider.
   * The prep\_and\_test\_testdir script will:
       * Check that the directory structure is as expected, and that the installed packages have expected versions. 
       * Add ssh and aliases to ${TEST\_DIR}/src/fabtests/bin/ to make it easier to set environment variables and capture test results
   * The prep\_and\_test\_testdir script also runs and validates that the zhpe-provider passes the following tests:
       * fabtests v1.6.1 (from OFIWG). This test suite exercises basic Libfabric functionality, 
         including 32 and 64 bit atomics.
       * OSU Microbenchmarks (from The Ohio State University). This test suite exercises MPI functionality, including:
         MPI\_Init, MPI\_Finalize, MPI\_Comm\_Size, MPI\_Comm\_Rank, Send, Receive, Barrier, Broadcast, Reduce, MPI\_Put, 
         MPI\_get, and 64 bit atomics (including both compare-and-swap and fetch-and-add)
       * a simple SNAP application (from the SNAP README), as an example MPI application.

# (Optional) Run a script that runs tests from the ibm onesided test suite
  * ${SCRIPT\_DIR}/run\_ibm\_onesided.sh -p ${TEST\_DIR}
  * This script exercises MPI functionality using some of the tests from the ibm test suite published in   
      the non-public Open MPI test repo ompi-tests. 
  * Tested functionality includes 32-bit atomic fetch-and-add and 32-bit compare-and-swap.
