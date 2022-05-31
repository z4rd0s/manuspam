from random import random
import pandas as pd
from sklearn.model_selection import train_test_split
import sklearn
from catboost import CatBoostClassifier, Pool

def preprocess(df):
    return df.drop_duplicates()

def score(y_true, y_pred):
    print("Accuracy:", sklearn.metrics.accuracy_score(y_true, y_pred))
    print("Precision:", sklearn.metrics.precision_score(y_true, y_pred))
    print("Recall:", sklearn.metrics.recall_score(y_true, y_pred))
    print("F1:", sklearn.metrics.f1_score(y_true, y_pred))
    print(f"Fbeta - 0,5: {sklearn.metrics.fbeta_score(y_true, y_pred, average='macro', beta=0.5)}")
    print(f"Fbeta - 0,95: {sklearn.metrics.fbeta_score(y_true, y_pred, average='macro', beta=0.95)}")
    print(f"Fbeta - 2: {sklearn.metrics.fbeta_score(y_true, y_pred, average='macro', beta=2)}")
    print('matthews_corrcoef: {}'.format(sklearn.metrics.matthews_corrcoef(y_true, y_pred) * 100))
    print('fowlkes_mallows: {}'.format(sklearn.metrics.fowlkes_mallows_score(y_true, y_pred) * 100))
    tn, fp, fn, tp = sklearn.metrics.confusion_matrix(y_true, y_pred).ravel()
    print("Confusion matrix")
    print(f"TN: {tn}, FP: {fp}, FN: {fn}, TP: {tp}")
    print()
    print()

ham = preprocess(pd.read_csv("../src/ham.csv"))
spam = preprocess(pd.read_csv("../src/spam.csv"))

dataset = pd.concat([ham, spam])
dataset = dataset.sample(frac=1)#.reset_index(drop=True)
dataset.head()

Y = dataset["Label"]
X = dataset.drop(columns=["Label", "Fname"])

X_train, x_test, Y_train, y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

train_data = Pool(
    X_train,
    label = Y_train
)

test_data = Pool(
    x_test,
    label = y_test
)

model = CatBoostClassifier(iterations=1000,learning_rate=1, depth=2, task_type="CPU")
model.fit(train_data, eval_set=test_data)

print("catboost Train-Data Scores")
preds_class = model.predict(train_data)
score(Y_train, preds_class)

print("catboost Test-Data Scores")
preds_class = model.predict(test_data)
score(y_test, preds_class)
