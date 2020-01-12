# JTrace
An old utility written before JSwat and other such utilities to perform binary instrumentation of running Java apps using the Java Debug Interface

# Description
This is an old, unsupported utility.  Run the application you want to reverse using debug interface -agentlib:jdwp=transport=dt_socket,server=y,suspend=y,address=localhost:8888.  JTrace will attach itself to the debug port and will be able to generate the list of loaded classes and allow you to debug any method or generate a call graph using graphviz.  

