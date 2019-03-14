## Usage

```python
import measure

android_measure = measure.AndroidMeasure('PACKAGE NAME e.g. com.android.chrome')
android_measure.start()
# play with the app
# ...
android_measure.stop()
print(android_measure.collect())
# Sample output: {'network': 0, 'cpu': [0.0, 0.0], 'memory': [1024, 1024], 'battery': 0.0}
# Units:          bytes         percentage         KB                      mAh
# CPU and memory usages are sampled every 5 seconds
```
