# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.0.1'
APPNAME='ndn-example'
CXXFLAGS= ['-std=c++14']

def options(opt):
    opt.load('compiler_cxx default-compiler-flags')

def configure(conf):
    conf.load("compiler_cxx default-compiler-flags")
    conf.env.CXXFLAGS = CXXFLAGS
    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'],
                   uselib_store='NDN_CXX', global_define=True, mandatory=True)

def build (bld):
    bld(target='producer_v1',
        features=['cxx', 'cxxprogram'],
        source=['producer_v1.cpp','ExecInstance.cpp'],
        use='NDN_CXX')
       
    bld(target='consumer_v1',
        features=['cxx', 'cxxprogram'],
        source='consumer_v1.cpp',
        use='NDN_CXX')
    bld(target='producer_v2',
        features=['cxx', 'cxxprogram'],
        source=['producer_v2.cpp','ExecInstance.cpp'],
        use='NDN_CXX')
       
    bld(target='consumer_v2',
        features=['cxx', 'cxxprogram'],
        source='consumer_v2.cpp',
        use='NDN_CXX')
    
    #bld(target='consumer_simple',
    #    features=['cxx', 'cxxprogram'],
    #    source='consumer_simple.cpp',
    #    use='NDN_CXX')
    bld(target='producer_simple',
        features=['cxx', 'cxxprogram'],
        source='producer_simple.cpp',
        use='NDN_CXX')
    bld(target='testApp',
        features=['cxx', 'cxxprogram'],
        source=['testApp.cpp','consumer_simple.cpp'],
        use='NDN_CXX')



