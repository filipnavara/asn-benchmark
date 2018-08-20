``` ini

BenchmarkDotNet=v0.11.0, OS=macOS Mojave 10.14 (18A347e) [Darwin 18.0.0]
Intel Core i5-7267U CPU 3.10GHz (Kaby Lake), 1 CPU, 4 logical and 2 physical cores
.NET Core SDK=2.1.301
  [Host]     : .NET Core 2.1.1 (CoreCLR 4.6.26606.02, CoreFX 4.6.26606.05), 64bit RyuJIT  [AttachedDebugger]
  DefaultJob : .NET Core 2.1.1 (CoreCLR 4.6.26606.02, CoreFX 4.6.26606.05), 64bit RyuJIT


```
|            Method |     Mean |     Error |    StdDev |
|------------------ |---------:|----------:|----------:|
| Serializer_Cached | 20.44 us | 0.3561 us | 0.3331 us |
| DerSequenceReader | 16.47 us | 0.3276 us | 0.5290 us |
|         AsnReader | 13.85 us | 0.3775 us | 0.3877 us |
