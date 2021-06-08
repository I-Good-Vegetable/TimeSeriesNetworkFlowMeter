from pathlib import Path
from typing import Union, Callable, Iterable, Dict, Collection, Optional, Any

import numpy as np
from numpy import savez_compressed
from scipy.sparse import csr_matrix, save_npz

from TimeSeriesNetworkFlowMeter.Log import logger
from TimeSeriesNetworkFlowMeter.Typing import FeatureSet, Features, TimeSeriesFeatureSet, TimeSeriesFeature


def s2us(s):
    return s * (10 ** 6)


def us2s(us):
    return us * (10 ** -6)


def returnArray(
        array,
        returnType: Union[type, Callable] = tuple
):
    if len(array) == 0:
        return
    if len(array) == 1:
        return array[0]
    else:
        return returnType(array)


def findIndex(array: Iterable, value):
    """
    Only suitable for small arrays

    :param array: The array
    :param value: The value to be found
    :return: The index of the value
    """
    valueIndex = None
    for index, name in enumerate(array):
        if name == value:
            valueIndex = index
    return valueIndex


def first(i: Iterable):
    return next(iter(i))


def mkdir(*, filepath=None, folder=None):
    if filepath is None and folder is None:
        raise ValueError(f'At least one of filepath '
                         f'and folderpath is not None')
    from pathlib import Path
    if filepath is not None:
        filepath = Path(filepath)
        folder = filepath.parent
    else:
        folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)


def arrays2csv(filepath, *arrays):
    delimiter = ','

    mkdir(filepath=filepath)

    with open(filepath, 'w') as f:
        for array in arrays:
            np.savetxt(
                f,
                array,
                fmt='%s',
                delimiter=delimiter,
            )


def addStatChar2Dict(
        d: dict,
        baseName: Optional[str],
        numList: Collection[Any],
        charMin=True,
        charMax=True,
        charSum=True,
        charMedian=True,
        charAve=True,
        charStd=True,
        defaultValue: float = 0,
) -> Dict:
    import statistics
    numList = [float(n) for n in numList]
    baseName = '' if baseName is None or baseName == '' else f'{baseName} '
    if charMin:
        d[f'{baseName}Min'] = min(numList) if len(numList) >= 1 else defaultValue
    if charMax:
        d[f'{baseName}Max'] = max(numList) if len(numList) >= 1 else defaultValue
    if charSum:
        d[f'{baseName}Sum'] = sum(numList) if len(numList) >= 1 else defaultValue
    if charMedian:
        d[f'{baseName}Median'] = statistics.median(numList) if len(numList) >= 1 else defaultValue
    if charAve:
        d[f'{baseName}Ave'] = statistics.mean(numList) if len(numList) >= 1 else defaultValue
    if charStd:
        d[f'{baseName}Std'] = statistics.stdev(numList) if len(numList) >= 2 else defaultValue
    return d


def features2array(
        features: Features,
        returnFeatureNames: True,
):
    keys, values = features.items()
    keys, values = np.array(list(keys)), np.array(list(values))
    if returnFeatureNames:
        return keys, values
    else:
        return values


def features2series(features: Features):
    import pandas as pd
    return pd.Series(features)


def featureSet2mat(
        featureSet: FeatureSet,
        returnFeatureNames: True,
):
    mat = np.array(
        [list(features.values())
         for features in featureSet]
    )
    names = np.array(list(featureSet[0].keys()))
    if returnFeatureNames:
        return mat, names
    else:
        return mat


def featureSet2df(featureSet: FeatureSet):
    import pandas as pd
    df = pd.DataFrame(featureSet)
    return df


def sortFeatureSet(featureSet: FeatureSet, accordingTo='Ts'):
    featureSet = sorted(featureSet, key=lambda features: features[accordingTo])
    return featureSet


def sortFeatureMat(featureMat, featureNames, accordingTo='Ts'):
    # colIndex, = np.where(featureName.flatten() == accordingTo)
    colIndex = findIndex(featureNames.flatten(), accordingTo)
    if colIndex is None:
        errMsg = f'Cannot find {accordingTo} in feature names'
        logger.error(errMsg)
        raise ValueError(errMsg)
    featureMat = featureMat[featureMat[:, colIndex].argsort()]
    return featureMat


def sortFeatureDf(featureDf, accordingTo='Ts'):
    featureDf = featureDf.sort_values(accordingTo)
    return featureDf


def featureSet2csv(
        filepath,
        featureSet
):
    """Save Feature Set to CSV File"""
    import csv
    with open(filepath, 'w', newline='') as csvFile:
        writer = csv.DictWriter(
            csvFile,
            list(featureSet[0].keys()),
        )
        writer.writeheader()
        writer.writerows(featureSet)
    logger.success(f'Feature set is saved to {filepath}')


def featureMat2csv(
        filepath,
        featureMat,
        featureNames,
):
    delimiter = ','
    np.savetxt(
        fname=filepath,
        X=featureMat,
        fmt='%s',
        delimiter=delimiter,
        header=delimiter.join(
            [str(featureName) for featureName in featureNames]
        ),
        comments='',
    )
    logger.success(f'Feature matrix is saved to {filepath}')


def featureDf2csv(
        filepath,
        featureDf,
):
    featureDf.to_csv(
        filepath,
        index=False
    )
    logger.success(f'Feature dataframe is saved to {filepath}')


def sortTimeSeriesFeatureSet(
        tsFeatureSet: TimeSeriesFeatureSet,
        accordingTo='Ts',
) -> TimeSeriesFeatureSet:
    def key(tsFeature: TimeSeriesFeature):
        basicInfo, _ = tsFeature
        return basicInfo[accordingTo]

    tsFeatureSet = sorted(tsFeatureSet, key=key)
    return tsFeatureSet


def featureSetDict2csr(
        featureSets: Dict[int, Features],
        subFlowLen,
        defaultValue,
) -> csr_matrix:
    assert len(featureSets) != 0
    nFeatures = len(first(featureSets.values()))
    mat = np.full((subFlowLen, nFeatures), defaultValue)
    for index, features in featureSets.items():
        mat[index, :] = np.array(
            list(features.values())
        )
    mat = csr_matrix(mat)
    return mat


def saveFeatureSetDictCsr(
        filepath,
        featureSets: Dict[int, Features],
        subFlowLen,
        defaultValue,
):
    mat = featureSetDict2csr(
        featureSets,
        subFlowLen,
        defaultValue,
    )
    save_npz(filepath, mat)


def saveTimeSeriesFeatureSet(
        folder,
        tsFeatureSet: TimeSeriesFeatureSet,
        subFlowLen=None,
        defaultValue=0.0,
        indexColName='Index',
        indexFilename='Index.csv',
        featureFilename='Features.npz',
):
    mkdir(folder=folder)
    if subFlowLen is None:
        from TimeSeriesNetworkFlowMeter.Flow import TimeSeriesFlow
        subFlowLen = TimeSeriesFlow.getSubFlowLen()
    basicInfoList = list()
    csrs = dict()
    for index, tsFeature in enumerate(tsFeatureSet):
        basicInfo, featureSets = tsFeature
        basicInfo[indexColName] = index
        basicInfoList.append(basicInfo)
        csrs[f'{index}'] = featureSetDict2csr(
            featureSets,
            subFlowLen,
            defaultValue,
        )
    featureSet2csv(
        str(Path(folder) / indexFilename),
        basicInfoList,
    )
    featureFilepath = str(Path(folder) / featureFilename)
    savez_compressed(featureFilepath, **csrs)
    logger.success(f'Time series feature set is saved to {featureFilepath}')
